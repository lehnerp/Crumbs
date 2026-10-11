# Crumbs: local forensic search dashboard

Point it at a folder full of logs, JSON, CSV, configs and anything else text-based.
Crumbs indexes every line into a single SQLite file, lets you search all of it at once,
shows the exact file and line of every hit, and runs automatic analysis on top.

## Quick start

```bash
pip install -r requirements.txt          # only dependency: Flask
python app.py /path/to/evidence          # indexes in the background, then open:
#   http://127.0.0.1:8765
```

Options:

| flag | meaning |
|---|---|
| `--db case42.db` | database file (default `crumbs.db` in the current folder) |
| `--port 9000` / `--host` | where to serve (binds to localhost only by default) |
| `--max-mb 500` | skip files bigger than this (default 200 MB) |
| `--full` | throw away the index and rebuild |
| `--no-index` | just open an existing database |

You can also start with plain `python app.py` and pick the folder in the UI (Index settings).
Re-indexing is incremental: only files whose size or modified time changed are re-read,
deleted files are dropped. Keep one `.db` per case.

## What you get

- **Search**: case-insensitive substring (default), exact case, or Python regex, across every
  line of every file. Filters for file type, path, and time range. Results are grouped by file with
  per-file counts; click any hit to open the file at that line. Leaving the query empty with a time
  range gives a merged, chronological "super-timeline" of all files.
- **File viewer**: line numbers, severity markers in the gutter, find-in-file (Enter / Shift+Enter
  or `n` / `N`), go-to-line, wrap toggle, SHA-256 of the original, download original. Scrolling
  loads more lines, so huge files are fine. Click a line number to pin it.
- **Findings**: built-in detection rules (secrets, AWS/GitHub/Slack tokens, private keys, JWTs,
  SQLi, XSS, path traversal, sensitive files, encoded PowerShell *with the payload decoded*,
  LOLBins/reverse shells, privilege changes, notable Windows event IDs, auth failures,
  scanner signatures, long base64 blobs, crashes, data exfiltration) plus the anti-forensics rules below.
- **Entities**: IPv4/IPv6 (classified public/private/etc.), domains, URLs, emails, MD5/SHA-1/SHA-256,
  MACs, CVEs, Windows paths, usernames. Windows paths are checked for plausibility, so regex
  escapes and binary noise that merely look like `k:\h'-(...` are not listed (existing databases
  are cleaned on start-up, no re-index needed). For each: every file and line it appears on, and which
  other entities share files with it ("found alongside") for pivoting.
- **Tampering timeline**: everything that points to deletion, wiping, log editing, timestamp
  manipulation, disabled logging, obfuscation or hiding, placed in time. A short summary names the
  busiest hour and the first sign of each kind; a lane chart (drag to zoom) sits above a strip of
  file modifications on disk; the list below links every signal to its file and line.
  See "Tampering signals" below for exactly what is checked.
- **Times while reading**: the viewer shows when each line was written in its own column. A line
  dated earlier than the lines above it is marked ⟲ in amber (inserted, edited in, or written after
  a clock change), and a dashed separator marks every unusual silence. Chips after a line show
  times it mentions: red **claims** for a time a command plants on a file or the clock
  (`touch -t/-d`, `.LastWriteTime =`, `date -s`, Sysmon `CreationUtcTime`), green **original** for
  the value it replaced (`PreviousCreationUtcTime`), and grey for numbers that decode to dates
  (Unix s/ms/µs, FILETIME, hex FILETIME, WebKit). Toggle the column with **Times**.
- **Line tab**: click any line for its full time story (real time of the action, time it tries to
  plant, original value, neighbouring timed lines) and **decoded content**: base64 (incl. UTF-16
  PowerShell, gzip, deflate), hex, `\x` / `\u` escapes, URL encoding, `[char]` / `fromCharCode` /
  `chr()` codes, PowerShell format-operator, backtick and concatenation tricks, reversed strings,
  ROT13 and single-byte XOR, applied up to three layers deep. Pin a decoding to the evidence board,
  or paste any text into "Decode other text".
- **Hidden commands**: while indexing, encoded parts of each line are decoded and the rules run on
  the result, so `wevtutil cl` or `history -c` hidden inside base64 shows up on the Tampering
  timeline as "hidden in base64 → gzip: …", dated by its line.
- **Integrity tab** in the file viewer: filesystem times, file type, entropy, NUL bytes, first and
  last entry, silences, time running backwards, missing record numbers, zeroed regions.
- **Timeline**: histogram of every timestamped line with findings overlaid; click a bar to read that
  slice across all files in time order. Recognises ISO 8601, Apache/nginx, syslog, `dd.mm.yyyy`
  and epoch fields in JSON.
- **Graph**: files and entities as a network; entities shared by several files become hubs.
  Double-click an entity to expand its neighbourhood, double-click a file to open it.
- **Evidence board**: pinned lines with notes, exportable as Markdown or CSV. Pins survive re-indexing.
- Dark theme by default, light theme toggle in the sidebar.

## Tampering signals

**Commands and events in the logs** (dated by the line they appear on): event logs cleared
(1102/104, `wevtutil cl`, `Clear-EventLog`), logs emptied or lines deleted (`> file`, `truncate`,
`sed -i '/x/d'`, `journalctl --vacuum`), shell history cleared or disabled, auditd / Sysmon /
Defender / rsyslog stopped, secure deletion (`shred`, `srm`, `sdelete`, `cipher /w`, `dd` from
`/dev/zero`), shadow copies and backups deleted, forced/recursive deletes, file deletion,
overwrite and rename records (USN journal, Sysmon 23/26, Security 4660, auditd), timestamp
changes (`touch -t/-d/-r`, `SetFileTime`, `.LastWriteTime =`, Sysmon event 2), clock changes,
obfuscation (base64 decoding, `certutil -decode`, `xxd -r`, PowerShell char/format/backtick
tricks, `eval(base64_decode(`), password-protected archives, hidden staging folders, `attrib +h`,
`chattr +i`, and web searches about clearing logs. Bash history with `#epoch` lines and zsh
extended history are dated per command.

**Evidence inside the files themselves**
- A log that starts with NUL bytes was emptied while a program still had it open (the classic
  `> /var/log/auth.log`); the first entry after the NULs says when writing resumed.
  Zeroed blocks inside a file are reported with the times just before and after them.
- Silences: a gap much longer than the log's usual spacing (at least 30 minutes and 25x the
  average) is reported with its start and end. Lines dated earlier than what came before them
  point to inserted entries or clock changes. Logs that mix sources (many small backward steps)
  are recognised and not flagged.
- Missing record numbers: `EventRecordID` (JSON/XML/CSV exports and `.evtx`) and auditd serials
  are checked for holes. A hole in a Windows event log means records were removed.
- Entries dated after the file's own modified time mean the modified time was set back.
- Files that are all NUL, empty, random-looking (entropy above 7.2 in a text-type file),
  OpenSSL-encrypted, carrying ransomware-style extensions, or whose content does not match
  their extension (a `.txt` that is a ZIP).

**Artifacts Crumbs now reads** (all with the standard library, nothing extra to install)
- Windows `.evtx`: record IDs, write times and the text strings of each record (usernames, IPs,
  paths, command lines, `LogFileCleared`). Binary XML is not decoded, so event ID numbers are not
  shown; export with `EvtxECmd` or `wevtutil qe /f:xml` for full fields.
- Recycle Bin `$I` files: original path, size and deletion time.
- Linux Trash `.trashinfo`: original path and deletion time.
- Vim swap files: who was editing which file, on which host, with which PID.
- SQLite databases (browser history, app databases): every table as text, with Chrome/WebKit,
  Firefox, Unix, FILETIME and Apple timestamps converted to UTC. Opened read-only and immutable.
- MFTECmd `$MFT` CSV (`SI<FN`, `uSecZeros`) and `$UsnJrnl:$J` CSV exports.
- Other binaries (executables, registry hives, raw `$MFT`, pcaps): printable ASCII and UTF-16
  strings with their byte offsets, so deleted file names and paths inside them are searchable.

**Filesystem metadata across the whole case**
- Modified times with exactly zero sub-seconds when the rest of the folder has sub-seconds
  (tools that set timestamps usually write whole seconds); on Linux, combined with an inode
  change time much later than the modified time, this is reported as a backdated file, dated by
  the change time.
- Bursts: many files modified within a short window (mass overwrite or encryption), with a note
  on how many now look random.
- Folders modified after everything they still contain: something was deleted or moved out,
  at the folder's modified time.
- Rotated logs missing from a sequence (`.1`, `.3` but no `.2`) and time gaps between rotations.
- Identical content under different names, different versions of the same name, and editor or
  backup leftovers (`.swp`, `~`, `.bak`, `.tmp`, `~$` lock files).

**Reading the results honestly**
- Filesystem times are only meaningful if they survived the copy. If nearly all files share the
  same time, Crumbs says so and suppresses the folder-based checks. Copying with `cp -a`,
  `robocopy /COPY:DAT /DCOPY:T`, or working from a mounted image keeps them.
- Access times are shown but unreliable (many systems update them lazily or not at all, and
  reading the evidence can change them). Crumbs records all times before it opens any file.
- Log times are shown as written in the log (often local time); filesystem times and decoded
  numbers are UTC. A time that a command on the line sets is never used as the line's own time.
- Gaps and backward jumps are prompts to look, not proof: quiet nights, restarts and
  daylight-saving changes produce them too. Missing record numbers and NUL-truncated logs are
  much stronger.
- Crumbs shows what is left in the folder. It cannot recover deleted content; for that, work
  from a disk image with tools such as The Sleuth Kit / Autopsy, MFTECmd or PhotoRec, and point
  Crumbs at their CSV output.

## Investigating a Linux / Debian host

Crumbs recognises Linux artifacts **by their path**, so index a copy that keeps the folder layout: a mounted disk image, or a collection such as

```bash
# on the suspect machine (or better: from a mounted image), as root
tar --numeric-owner --xattrs -cpzf host.tgz \
    /etc /var/log /var/lib/dpkg /var/spool/cron /home /root /tmp /var/tmp /dev/shm \
    /bin /sbin /usr/bin /usr/sbin /usr/local /usr/lib/x86_64-linux-gnu/security /var/www
```

`-p` keeps permissions (needed for the SUID check) and modification times. Extract it anywhere and point Crumbs at the folder.

### What is parsed

| Artifact | What Crumbs gets from it |
|---|---|
| `etc/passwd`, `shadow`, `group` (and the `-` backups) | accounts, UID 0 clones, system accounts that can log in, empty or weak passwords, password-change dates, root-equivalent groups, accounts added or removed since the backup copy |
| `sudoers`, `sudoers.d/*` | NOPASSWD rules, sudo logging switched off |
| `authorized_keys`, `sshd_config`, `known_hosts` | every key with its SHA256 fingerprint, forced commands, risky server settings (root login, extra ports, `LogLevel QUIET`, extra key files), SSH targets |
| `auth.log`, `secure`, `syslog`, journal text exports | logins per source, sudo and su, account changes, sshd listening ports |
| `wtmp`, `btmp`, `utmp`, `lastlog` (binary) | sessions, failed logins, reboots; **zeroed records** (what log cleaners leave), records out of order, partial records |
| `audit/audit.log` | commands rebuilt from hex-encoded `EXECVE` arguments with user (auid) and folder, audit rules removed |
| `apt/history.log`, `dpkg.log` | installs and removals, who asked, full command line |
| cron, systemd units, `rc.local`, `init.d`, shell startup files, `ld.so.preload`, `pam.d`, `modules` | persistence, with the reason each entry stands out (downloads, pipes to a shell, temp or hidden paths, reverse shells, aliases that hijack `sudo`, `pam_exec`, ...) |
| `var/lib/dpkg/info/*.md5sums`, `*.list`, `status` | **package verification**: system programs that differ from their Debian package, programs no package installed, changed security config files |
| `.viminfo`, `.wget-hsts` | files edited in vim with times, hosts downloaded from with times |
| `os-release`, `hostname`, `timezone`, `localtime` | host identity and time zone |

### Correlations across files

Password guessing that ended in a login (with the first successful login); root logging in from a public address;
**logins with an SSH key that is in no collected `authorized_keys`** (planted, used, then removed); ELF programs in temporary or hidden folders;
SUID programs outside the package lists; deceptive names such as `...` or trailing spaces.

### The Host view

One page for the machine: what needs attention, accounts with flags, logins by source, SSH keys and their use,
sshd settings, sudo/su/account changes in time order, persistence, system-file integrity, packages, rebuilt commands, and contacts.
Every row opens the line it came from. Syslog-style logs are in the machine's **local time**; wtmp, lastlog, auditd, shadow dates,
decoded epochs and file times are **UTC**. The Host view shows the time zone so you can line them up.

### Eavesdropping and traffic manipulation

Crumbs looks for signs the machine was used to **watch or tamper with network traffic**, from logs, configuration and any capture files left behind:

- **Listening:** the kernel logging an interface entering *promiscuous mode*, auditd's `ANOM_PROMISCUOUS` (which records the user), and sniffer tools (`tcpdump -w`, `tshark`, `dumpcap`, `ngrep`, the dsniff suite, raw-socket / `AF_PACKET` code, `setcap cap_net_raw`).
- **Man-in-the-middle:** ARP spoofing tools (`arpspoof`, `ettercap`, `bettercap`, `responder`) and kernel / arpwatch ARP warnings; IP forwarding turned on (command or `sysctl.d`); NAT `REDIRECT` / `DNAT` / `NFQUEUE` / `TPROXY` rules (in commands or in `iptables/rules.v4`, `nftables.conf`); DNS tampering (`/etc/hosts` entries, odd `resolv.conf` resolvers, dnsmasq `address=`, `dnsspoof`, `dnschef`); TLS interception (`sslstrip`, `mitmproxy`, a CA added under `/usr/local/share/ca-certificates`); route and neighbour changes; `tc netem` shaping.
- **Capture files** (`.pcap`, `.pcapng`, `.cap`): Crumbs parses them into one readable, timestamped line per packet, so the viewer, search and timeline work on them. From the packets it recovers the **capture window**, top talkers and ports, **ARP anomalies** (one IP answered by several MACs, or one MAC claiming many IPs — the fingerprint of ARP spoofing), and **plaintext credentials** in the traffic (HTTP Basic and form logins, FTP, POP3, IMAP, SMTP auth). Captured credentials are searchable like any decoded content.

These are grouped into the same **numbered episodes** as the floods: *Network eavesdropping* or *Traffic manipulation / man-in-the-middle*. Dated signals within 30 minutes form one episode; standing configuration with no timestamp (a rules file, a `sysctl.d` drop-in, an added CA) attaches to the episode whose window matches its file's change time, or forms one "configuration left in place" episode. Each episode is tagged `EP#n` in every file that shows it (viewer badge, `ep:n` search) and appears in the Host view under **Eavesdropping & traffic manipulation** and on the Intrusion timeline.

### Floods and starvation (SMTP abuse, resource exhaustion)

Crumbs counts mail and connection activity **per minute** from:

- **Exim** `exim4/mainlog` (Debian's default MTA): messages accepted (`<=`) with the submitting user (`U=www-data`) and script folder (`cwd=`), deliveries, deferrals, bounces, connections, timeouts, refusals, frozen messages
- **Postfix / sendmail / msmtp** lines in `mail.log` or syslog: pickup `uid=`, `qmgr` messages, `to= … status=`, `connect from`, `lost connection / timeout after`, `reached its process limit`, rate/concurrency limits
- **Firewall / kernel** (`kern.log`, `ufw.log`, conntrack events): connections **leaving this machine** to port 25/465/587, the evidence for starving other mail servers; SYN-flood warnings, conntrack table full, OOM kills, full disk, fork failures
- the **mail queue** left in `var/spool/exim4/input` or the Postfix queue folders

Minutes far above the machine's normal rate (5× its busy level over the whole logged period, and at least 30 events a minute) are
grouped into **numbered episodes**: *SMTP flood* (mass mail through this host), *Outbound SMTP connection flood* (connection
starvation of other servers), *SMTP service saturated*, *Resource starvation*. Overlapping aspects form one episode.

Each episode is **tagged**:

- in the viewer: an "Episode #n starts here" marker and an `EP#n` badge on every line of the episode, in every file that shows it;
- in the Line tab: "During episode #n", with buttons for all its lines, everything in its window, and its details;
- in search: `ep:1`, `ep:1,2`, `-ep:2`, combined with anything else (`ep:1 "=="` = the deferrals of episode 1);
- as findings on the Intrusion timeline (with start and end), and in the Host view under **Floods & starvation**.

The Host card shows a per-minute chart, messages, deliveries, targets (recipient domains, remote servers, destination IPs),
who submitted the mail and from which folder, and **what started it**: flooding tools, mail loops and web-shell activity
from 15 minutes before the start, plus scripts whose file changed in that window. Flooding tools, loops (`for … do sendmail`,
`while true; do nc host 25`, PHP `foreach … mail()`, Python `smtplib` loops), `swaks`, `hping3 --flood`, `slowloris` and
fork bombs are rules of their own.

Times are compared as written: Exim writes its own timestamps (normally local time, like syslog), firewall lines in kern.log
are syslog local time, shell history and auditd are UTC.

## Triage: judging findings, and teaching Crumbs

The **Triage** view is a ranked queue of findings with the evidence in context. For each one choose **Valid**, **False positive** or
**Unsure** (keys <kbd>V</kbd> <kbd>F</kbd> <kbd>U</kbd>, move with <kbd>J</kbd>/<kbd>K</kbd>, open the file with <kbd>O</kbd>), and how far the verdict reaches
(<kbd>1</kbd>–<kbd>5</kbd>):

1. just this finding
2. the same text pattern everywhere (numbers, IPs, hashes and times ignored)
3. this rule in this file
4. this rule everywhere
5. any finding mentioning a value — as *false positive* this marks a value benign (e.g. your admin's IP); as *valid* it records a confirmed IOC

Broad verdicts are **previewed** before they are saved: how many findings, which severities, samples, and warnings such as
"dismisses 7 high-severity findings" or "also dismisses findings of other rules". Every verdict can be undone.

Verdicts are kept outside the indexed data, so they survive re-indexing and rebuilds and are re-applied to the new findings. What they change:

- **False positives** disappear from the timelines, Host view, stories and the Findings list (a switch shows them again, struck through); benign values also drop out of the remote-control and initial-access tables.
- **Rule reliability**: each rule gets a precision estimate from your explicit judgements (value-based dismissals don't count), which re-ranks the queue and is shown under *What Crumbs learned*.
- **Confirmed IOCs**: IPs, domains, URLs, e-mails, hashes, accounts and suspicious paths on confirmed lines (plus IOCs you add by hand) become confirmed indicators. Findings that mention them, or happen within 30 minutes of confirmed activity, rise to the top of the queue; channels that involve them are marked *confirmed IOC* in the Host view.
- **Leads**: lines that mention a confirmed IOC but are not part of any judged finding — the places the automatic analysis did not flag.

The queue is fully paged (200 at a time, with Prev/Next and the total), and can be ordered by **most important**, **newest first**,
**oldest first**, or **by severity**, and filtered by status, severity, category and free text. A per-day **timeline strip** above the
queue shows how many findings fall on each day and how many are still unreviewed (red); click a day to jump to it.

## Debian baseline diff (ordinary Debian vs. not)

The Host view's **Debian baseline** section answers one question for the whole machine: what is standard Debian, and what is not?
Using dpkg's own records (the `.md5sums` and `.list` files under `/var/lib/dpkg/info`, and the conffile hashes in `/var/lib/dpkg/status`),
it classifies every file under the system tree (`/bin`, `/sbin`, `/lib*`, `/usr`, `/etc`, `/boot`):

- **standard** — present and matches the checksum its package recorded;
- **modified** — present but different from its package (a config you changed, or a trojaned binary like a tampered `/usr/bin/ls`);
- **unowned** — a file in a system folder that no installed package put there (a dropped binary, an added unit, a planted config);
- **unverifiable** — owned but with no recorded md5 (directories, generated files) or no hash computed;
- **missing** — a file a package expects that is not in the evidence (only counted when the collection looks whole).

Local content that is normal to find unpackaged — your network config, SSH host keys, certificates, `cron.d` drop-ins, everything
under `/var` and `/usr/local/share` — is excluded, so what remains under "unowned" is genuinely extra.

It also **diffs the installed package set** against a base-Debian set, separating offensive / dual-use additions (nmap, socat,
tcpdump, tor, wireguard-tools, …) from ordinary server packages (nginx, php, htop) and other extras. A proportion bar summarises the
file classes at a glance, and every row opens the file. The per-file results also feed Triage and the timelines as the existing
`pkg_file_modified`, `conffile_modified` and `unowned_binary` findings.

This needs `/var/lib/dpkg` collected alongside the system folders. Without it the section explains what to collect. If most files
appear "modified", Crumbs warns that the collected dpkg records are probably for different package versions than the binaries.

## Full filesystem dumps: deleted files and reset timestamps

Point Crumbs at the root of a dumped or mounted Debian system (the folder holding `etc/`, `usr/`, `var/lib/dpkg/`);
any release works, including stretch. Crumbs then checks every file, folder, link and device node against dpkg's own
records from the dump (Filesystem view, and a section in the report):

- **Timestamps set back**: a file that differs from its package but is dated before dpkg installed that package; an
  added file with the exact time of a neighbouring package file (`touch -r`); whole-second times among sub-second
  neighbours (`touch -d/-t`). If shell history holds the `touch` command, the finding gets its real time.
- **Deleted**: paths used in commands that are gone (marked when `rm`/`shred` was on the same line), logs rsyslog
  writes that are missing, inspection tools removed while their package is installed, folders changed after
  everything they still hold, files owned by deleted accounts, packages removed (security packages flagged high).
- **Hidden or planted**: hidden names in system folders, programs in temp/web/hidden folders, unpackaged kernel
  modules, regular files in `/dev`, history files linked to `/dev/null`.
- **`[crumbs]/filesystem-timeline.txt`**: a generated, searchable UTC timeline of every changed, added, removed
  and package event. Episodes tag it by time, so `ep:N` includes filesystem changes.

What survived the copy is measured, not assumed: if inode change times were reset by copying (usual for a copied
tree), checks that need them are skipped and the view says so. Analysing a read-only mount of the image keeps them.
For deleted file names and creation times, run Sleuth Kit `fls -r -m / disk.img > bodyfile.txt` and put the
bodyfile in the evidence folder. Files byte-identical to their package are verified but not text-indexed, and
`/proc` and `/sys` are skipped, so a full dump indexes in minutes rather than hours.

## Login world map

Overview and Host → Logins by source show where every login came from: red markers for addresses that logged in
(numbered, pulsing, labelled), amber for failed-only sources sized by volume, a ring for confirmed IOCs or addresses
threat intel calls malicious. Click a marker or country for the addresses, accounts used and tried, time range and
a jump to the first login line. Internal addresses are listed separately.

Locations, best first: an offline city database (put a free DB-IP City Lite or GeoLite2-City `.mmdb` in `geo/`,
read by a built-in reader, nothing is sent anywhere), otherwise Shodan coordinates or the AbuseIPDB/VirusTotal country
from lookups you already made. "Look up with your intel keys" on the map fetches the rest.

## Compressed files and archives

Compression is recognised by content, not by name: gzip, bzip2 and xz files are read decompressed wherever they are
(`auth.log.2.gz`, `auth.log.6.bz2`, `access.log.5.xz`, a gzipped file without `.gz`, `wtmp.1.gz`, `x.pcap.gz`), and
rotated logs in any of those formats count as their log type. A compressed file that is cut short or damaged is not an
error: everything that still decodes is indexed and the file is flagged (*Compressed file ends early or is damaged*),
which is typical of a rotation that was truncated or partly overwritten.

Archives are opened too: tar (plain, .tar.gz/.tgz, .tar.bz2, .tar.xz) by content, and `.zip` files. Their files are
unpacked into `<database>.extracted/` next to the database (never into the evidence) and indexed as
`archive.tar.gz!/path/inside`, with the times stored in the archive; one archive inside another is opened as well.
Archived files are searchable and run through every rule, but are not merged into the Host picture (an archived
`/etc/passwd` may come from another machine). Flagged: archives that end early (files before the break are kept) and
member names that climb out of the unpack folder (`../`, absolute paths). Limits: 20,000 entries / 4 GB per
archive, members larger than the size limit are skipped, encrypted zip members are not read. Not handled: 7z, rar,
zstd, and Office/Java/Android zips (`.docx`, `.jar`, `.apk`), which stay whole.

## Investigation report

The **Investigation report** button on the Overview compiles everything Crumbs worked out into one Markdown document you can read,
copy or download: the headline numbers, how the attacker got in, the control channels and tunnels, the attack episodes (floods,
eavesdropping, MITM), the Debian baseline diff, the non-standard tools with their MITRE techniques, your confirmed findings and IOCs
(with any threat intel), and the open leads. It reflects your Triage verdicts — dismissed findings are left out and confirmed ones are
highlighted — so it is a live summary of the case as you have reviewed it, not a raw dump.

## Threat intelligence (VirusTotal, Shodan, AbuseIPDB)

Crumbs can enrich indicators with external threat intel, but **only with your own API keys and only when you ask** — it never
calls out on its own. Add keys under **Settings & keys** (all free tiers work); they are stored only in this case's database and are
sent only to the matching service.

- **File hashes → VirusTotal**: detection ratio, threat label, type, first-seen, reputation.
- **Public IPs → Shodan**: open ports, running products, known CVEs, tags, owner/ASN/location, hostnames.
- **Public IPs → AbuseIPDB**: abuse-confidence score, number and categories of reports, Tor-exit and allowlist flags.
- VirusTotal also takes domains and URLs.

Each finding's detail panel lists the IPs, hashes and domains on that line — plus the **SHA-256 of the file itself** — with a pill per
provider; click to look one up or "Look up all". The **Entities** view also carries intel: every public IP, hash and domain shows a
coloured assessment pill (malicious / suspicious / clean) inline in the list, or an "intel: look up" button when nothing is cached
yet, and selecting an entity opens a full panel with the Shodan ports/CVEs/owner, the AbuseIPDB score and report categories, and the
VirusTotal detections, each with a link to the provider. Private and loopback addresses are left alone. Results are cached in the
database with the time fetched, so they are instant afterwards and work offline. From Settings you can **enrich every confirmed IOC in bulk**; it paces itself for the free VirusTotal
rate limit and stops cleanly if a service rate-limits, keeping whatever it already fetched. A one-line assessment
(malicious / suspicious / unknown) is derived from the combined results.

## Non-standard tools (not part of base Debian)

The **Tools** view inventories tools an intruder brings that a clean Debian install does not ship, grouped by purpose:
proxies and tunnellers (socat, chisel, frp, sshuttle, 3proxy, microsocks, gost, …), VPN / mesh / anonymity (Tor, WireGuard,
Tailscale, ZeroTier, OpenVPN, nebula), censorship-evasion / C2 transports (shadowsocks, v2ray, xray, trojan, hysteria),
DNS / ICMP tunnels (iodine, dnscat2, dns2tcp, dnstt, ptunnel, hans), web tunnels (reGeorg, Neo-reGeorg, Tunna, pystinger, suo5,
reDuh), sniffers and MITM (tcpdump, tshark, ngrep, dsniff, ettercap, bettercap, sslstrip/sslstrip2, mitmproxy, singularity),
scanners (nmap, masscan, nuclei, gobuster, …), exploit and cracking kits (sqlmap, hydra, hashcat, impacket, crackmapexec,
metasploit, sliver, pwncat), post-exploitation (linpeas, pspy, mimipenguin, lazagne), rootkits (diamorphine, reptile, …),
miners (xmrig, …), and offensive middleware (rack-attack).

Each tool is an expandable card listing **every place it leaves a trace**, and each one links straight into the evidence: the file
name opens the viewer, the sample line opens at that line, and a row of line-number buttons jumps to each specific occurrence. A card
also shows the tool's **MITRE ATT&CK techniques** (e.g. a sniffer → T1040 Network Sniffing, T1557 Adversary-in-the-Middle). For each
tool the breadcrumbs are a **dropped binary** (in a program folder, with no owning package), an **extra apt/dpkg install**, a
**config file** the tool uses, or a **mention** in logs, shell history, scripts or decoded content — ranked so a dropped binary or
config stands above a bare mention. Offensive tools raise a finding on any trace; dual-use ones (a proxy, a VPN) only when they
are actually installed or configured on the host, not merely named. This is scanned over the stored evidence each analysis pass, so
it stays complete on an incremental re-index.

## Web compromise, remote control and hidden tunnels

**Access logs** (Apache / nginx, combined or common format) are analysed per client and per script:

- exploit families (Log4Shell, Shellshock, RCE parameters, LFI/RFI, SQLi, SSTI, XXE, known exploit paths such as PHPUnit `eval-stdin.php`, wp-file-manager, ThinkPHP, Spring), aggregated per client, and those the server **answered successfully**;
- **web shells**: scripts flagged as shells (or scripts in upload folders) mapped to their URL, with first request, who used them and for how long;
- **initial access**: candidates in time order — the upload that planted the shell (a POST to an upload handler shortly before the shell file's time and first use), exploits answered 200, SSH password guessing, SSH keys removed after use. The *most likely foothold* is the earliest high-confidence step; earlier successful steps (often reconnaissance) and later stages are labelled.

**Remote control over time** (Host view → *Remote control & tunnels*):

- **beaconing**: regular polling detected from the gaps between requests (a fixed interval with little jitter), for web-shell use and for outbound connections in firewall logs;
- **HTTP tunnels through a script** (reGeorg / Neo-reGeorg / suo5 style): floods of POSTs to one script, `cmd=connect&target=…&port=…` requests;
- **control over days** through the same script, and **use from inside the network**: internal addresses using the attacker's web shell or tunnel, or logging in as an attacker-created account, after the compromise began (and, separately and weaker, internal addresses first seen after it);
- **covert tunnels**: Tor (hidden services exposing SSH, `.onion`), WireGuard / Tailscale / ZeroTier / OpenVPN / nebula, socat / ncat relays, rinetd and SOCKS proxies, DNS tunnels (iodine, dnscat, dns2tcp, dnstt — and detected from query patterns in dnsmasq / bind logs and captures: many long random subdomains), ICMP tunnels (ptunnel, icmpsh, hans — and large echo payloads in captures), sshd port-forwarding traces, xray / v2ray / shadowsocks, and their configuration files (`/etc/tor/torrc`, `/etc/wireguard/*.conf`, `*.ovpn`, `frpc.ini`, cloudflared, ngrok, …);
- **live sockets**: in `ss` / `netstat` / `lsof` output collected from the running system, connections or listeners held by shells, interpreters, relays, deleted programs or programs in temporary or hidden locations.

Normal traffic is filtered out: scripts used by many clients (index pages, carts, logins) are not treated as shells or control channels, and uptime monitors on public pages are not beacons.

## Searching deeper

- **Boolean** mode: `wget /tmp` (both words, any order), `"history -c"` (phrase), `curl OR wget`, `-Failed` (exclude),
  `file:auth.log`, `ext:log`, `after:2024-03-14T02:30 before:2024-03-14T03:00`, `rule:ssh_*`, `sev:high`, `cat:persistence`,
  `has:finding`, `has:decoded`, `has:time`, `ep:1` (lines of flood / starvation episode 1).
- **Decoded content is searchable.** Whatever Crumbs decodes (base64, gzip, hex, URL/char escapes, auditd arguments) is indexed
  separately. Searches show "Found inside decoded content" hits: a `wget` hidden in base64 in `.bash_history` or split across
  auditd hex arguments is still found.
- **IOC sweep** (button in Search): paste a list of IPs, domains, hashes, file names or commands; each gets line, file and decoded
  counts with first and last time seen.
- **Around this time**: in a line's Line tab, "Everything, all files ±5 min / ±30 min / ±2 h" lists every timed line from every file
  in that window, in time order.
- **Tampering view** has three sets: *Covering tracks*, *Intrusion* (logins, privilege, persistence, tooling, rootkits, web shells,
  lateral movement) and *Everything*.

## How it works

- `indexer.py` walks the folder, records every file's and folder's timestamps first, profiles
  each file's bytes (type, entropy, NUL regions), decompresses `.gz`, pretty-prints minified JSON
  so line numbers are meaningful, and stores each line in SQLite. `artifacts.py` holds the
  readers for EVTX, `$I`, Vim swap, SQLite and binary strings.
- Search uses an **FTS5 trigram index**, so arbitrary substrings (IPs, hash fragments, paths,
  punctuation) are found in milliseconds. Terms shorter than 3 characters and regexes fall back
  to a scan, capped at 20 seconds.
- `analyzers.py` holds all regexes for entities, rules and timestamps. Add a rule by appending
  one tuple to `_RULES` (id, severity, category, description, regex, pre-check keywords), then
  re-index with "Rebuild from scratch".

## Good to know

- Databases from older versions are rebuilt automatically on first start (schema 3). Evidence-board pins are kept.
- Package verification needs `var/lib/dpkg/info` **and** the program folders in the same collection. A mismatch means the file
  differs from what the package installed: a trojan, or a legitimate update or local change; check the file's time and content.
- Threat-intel lookups need network access and your own API keys (Settings & keys); without keys, everything else works unchanged and indicators simply show "needs key". Keys and cached results live in the case database and survive re-indexing.
- If you have it, add live-response output (`ss -tanp`, `netstat -antp`, `lsof -i`, `ps auxf`) to the evidence folder: it is searched and checked like any log.
- The SUID check only runs when permissions survived the copy (`tar -p`, `cp -a`, or a mounted image).
- A capable attacker edits logs. Compare sources: auth.log against wtmp, btmp and lastlog; auditd against shell history;
  file times against log times. Crumbs points at disagreements; judge each one.

- Evidence is only ever **read**, never modified.
- Expect the database to be roughly 4-5x the size of the text it indexes (the trigram index is
  what makes substring search fast). Indexing runs at roughly 7k lines per second.
- Databases made by an earlier version are rebuilt automatically on first run (your pinned
  evidence is kept); the first indexing run afterwards is a full one.
- Syslog lines have no year; Crumbs uses the file's modified-time year, stepping back a year for
  entries that would otherwise land more than a month after the file was last written.
- No authentication: keep it on `127.0.0.1` unless you put it behind something that has auth.
- Needs Python 3.8+ with SQLite 3.34+ for the trigram index (standard in current Python builds).
  Without it, search still works via slower full scans.
- The graph library (Cytoscape.js, MIT licence) ships in `static/vendor/` so the tool works
  offline. Fonts load from Google Fonts when online and fall back to system fonts otherwise.
