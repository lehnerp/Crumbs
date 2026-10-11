# Crumbs

**A local forensic search dashboard for Linux / Debian compromise investigations.**

Point Crumbs at a folder of collected evidence (logs, configs, shell history, packet captures, or a whole
filesystem dump) and it indexes every line into a single SQLite file, runs well over a hundred detection rules, and
gives you a browser dashboard to search, triage and reconstruct what happened. It runs entirely on your own
machine, needs only Python and Flask, and never modifies the evidence.

<!-- Add a screenshot: docs/screenshot-overview.png -->
<!-- ![Crumbs overview](docs/screenshot-overview.png) -->

---

## What it does

**Search everything at once**
- Substring, case-sensitive, regex and boolean search across every line of every file, with filters for path,
  type and time range. Every hit opens the file at the exact line.
- Leave the query empty and set a time range to get one merged timeline of all files.
- Text Crumbs decodes (base64, hex, URL escapes, gzip, auditd arguments) is indexed too, so a `wget` hidden in a
  base64 string in `.bash_history` is still found.

**Find what matters**
- Detection rules for credentials and secrets, web shells and exploit attempts, reverse shells and LOLBins,
  persistence (cron, systemd, rc.local, PAM, `ld.so.preload`, SSH keys), privilege changes, rootkits, miners,
  covert tunnels (Tor, WireGuard, socat, DNS/ICMP tunnels), sniffing and man-in-the-middle, and log tampering.
- **Triage queue** with valid / false-positive / unsure verdicts that can be scoped from one finding to a whole
  pattern; Crumbs re-ranks the remaining queue from what you confirm.
- **Corroboration**: every finding, address and episode shows how many independent log sources back it up.

**Reconstruct the host**
- **Host view**: accounts, logins by source, SSH keys, sudo and su, persistence, executed commands, the most
  likely way in, and remote-control channels.
- **Episodes**: bursts of activity grouped and numbered (SMTP floods, outbound connection floods, resource
  starvation, DHCP pool starvation with the spoofed MAC prefix, eavesdropping and MITM). Episode markers appear
  in every file, and each episode exports as PDF or XLSX evidence.
- **Login world map** of where logins came from, separating successful logins from brute force.
- **Non-standard tools**: over 130 offensive and dual-use tools (nmap, chisel, frp, sliver, diamorphine, xmrig,
  …) found in package logs, binaries, configs, bash completions and history, with a plain-language description
  and MITRE ATT&CK mapping for each.

**Catch anti-forensics on a full filesystem dump**
- Checks every file against dpkg's own records from the dump: what is standard Debian, what was modified, what no
  package installed.
- Finds **timestamps that were set back or copied** (`touch -d`, `touch -r`), and dates them from shell history
  when the command is there.
- Finds **what was deleted**: paths used in commands that are gone, missing logs, removed inspection tools,
  folders that lost entries, files owned by deleted accounts, and removed security packages.
- Measures what survived your collection method (inode change times, sub-second precision, completeness) and
  only runs the checks the evidence supports.
- Generates a searchable filesystem timeline. Reads a Sleuth Kit bodyfile for deleted file names and
  creation times.

**Reads what's actually in a dump**
- gzip, bzip2 and xz detected by content; truncated or damaged compressed logs are recovered as far as they
  decode, and flagged.
- tar (plain, `.tar.gz`, `.tar.bz2`, `.tar.xz`) and `.zip` archives are unpacked next to the database and their
  files indexed individually, including archives inside archives.
- Binary artifacts: `wtmp`/`btmp`/`lastlog`, pcap/pcapng (credentials, DNS and ICMP tunnels, ARP spoofing), EVTX,
  SQLite, the systemd journal exported as text, and printable strings from programs.

**Optional enrichment**
- VirusTotal, Shodan and AbuseIPDB lookups with your own API keys; results are cached in the case database.
- Offline geolocation from a free DB-IP or MaxMind `.mmdb` file.
- A Markdown investigation report generated from everything above.

---

## Quick start

```bash
git clone https://github.com/lehnerp/crumbs.git
cd crumbs
pip install -r requirements.txt
python app.py /path/to/evidence --db case.db
```

Then open **http://127.0.0.1:8765**. Indexing runs in the background and the dashboard fills in as it goes.

| Option | Meaning |
|---|---|
| `--db case.db` | Database file for this case (default `crumbs.db`). Keep one per case. |
| `--port 8765`, `--host 127.0.0.1` | Where to serve. Localhost only by default. |
| `--max-mb 200` | Skip files larger than this. |
| `--full` | Rebuild the index from scratch. |
| `--no-index` | Open an existing database without re-indexing. |

You can also run `python app.py` alone and choose the folder under **Index settings**. Re-indexing is
incremental: only changed files are read again. Verdicts, IOCs, pins, API keys and intel results survive a full
rebuild.

**Requirements:** Python 3.8+ with SQLite 3.34+ (for the trigram search index; standard in current Python
builds). Linux, macOS and Windows. Flask is the only required package; `reportlab` and `openpyxl` enable the PDF
and XLSX exports, and `numpy`, if installed, speeds up file profiling.

---

## Collecting evidence

Crumbs works with whatever you have, but gets much more out of a complete picture.

- **Logs only:** copy `/var/log`, `/etc`, `/home/*/.bash_history`, `/root`, crontabs and `/var/lib/dpkg`.
- **Full filesystem (best):** point Crumbs at the root of the dump, the folder containing `etc/`, `usr/` and
  `var/lib/dpkg/`. `/proc` and `/sys` are skipped, and files identical to their Debian package are verified but not
  text-indexed, so large dumps stay fast.
- **Use a read-only mount of the image rather than a copied tree if you can.** Copying resets inode change
  times, which are the strongest evidence against reset timestamps. Crumbs detects a copied tree and says so.
- **Deleted files:** run Sleuth Kit on the disk image and drop the result into the evidence folder:
  ```bash
  mmls disk.img                                   # find the Linux partition's start sector
  fls -r -m / -o 2048 disk.img > bodyfile.txt
  ```
  On Windows, use the Sleuth Kit Windows build from `cmd.exe` (PowerShell's `>` writes UTF-16).
- **Live response output** (`ss -tanp`, `ps auxf`, `lsof -i`) placed in the folder is searched and checked like
  any log.

---

## Optional setup

**Threat intelligence.** Add VirusTotal, Shodan and AbuseIPDB keys under **Settings & keys**. Lookups only
happen when you ask for them. Without keys, everything else works.

**Offline geolocation for the login map.** Put one MaxMind-format city database in `geo/`:
- [DB-IP IP to City Lite](https://db-ip.com/db/download/ip-to-city-lite) (free, no account, CC BY 4.0;
  attribution to DB-IP is required if you publish maps made with it), or
- MaxMind GeoLite2-City (free account).

Crumbs reads it with a built-in reader; no addresses are sent anywhere. Without a database, the map uses
locations from your intel lookups.

---

## How it works

| Module | Role |
|---|---|
| `app.py` | Flask API and server |
| `indexer.py` | Walks the evidence, profiles and decodes files, stores lines in SQLite with an FTS5 trigram index |
| `artifacts.py` | Compression, archives, binary formats (EVTX, SQLite, strings, Recycle Bin, Vim swap) |
| `analyzers.py` | Entity extraction, detection rules, timestamp parsing |
| `linux.py` | Host artifacts: auth, sudo, cron, systemd, PAM, SSH, dpkg, wtmp/btmp/lastlog |
| `traffic.py`, `pcap.py` | Floods, starvation, sniffing episodes; packet capture parsing |
| `webaccess.py` | Web logs: exploits, web shells, beacons, initial access, tunnels |
| `fsweep.py`, `baseline.py` | Whole-filesystem checks against dpkg; Debian baseline diff |
| `toolhunt.py` | Non-standard tool catalogue |
| `triage.py`, `corroboration.py` | Verdicts, ranking, leads; independent-source scoring |
| `intel.py`, `geo.py` | Threat-intel lookups; offline geolocation and the world map |
| `report.py`, `export.py` | Markdown report; PDF and XLSX episode evidence |
| `static/` | The single-page dashboard (vanilla JavaScript) |

**Adding a detection rule:** append one tuple to `_RULES` in `analyzers.py` (id, severity, category,
description, regex, pre-check keywords), then rebuild the index.

The full guide to every view, rule family and check is in **[docs/MANUAL.md](docs/MANUAL.md)**.

---

## Limitations and caveats

- **Findings are leads, not conclusions.** Rules and correlations point at what deserves a look; confirm each
  one against the source line, which is always one click away.
- **A capable attacker edits logs.** Crumbs compares sources against each other (auth.log against wtmp and
  btmp, auditd against shell history, file times against log times) and shows where they disagree.
- **Timestamps:** syslog-style logs carry no year or time zone. Crumbs infers the year from the file and shows
  the system time zone; wtmp, auditd, file times and decoded epochs are UTC.
- **Debian-focused.** Host analysis and the dpkg checks assume Debian or a derivative (checked against stretch,
  bookworm and Ubuntu systems). Other distributions still get search, rules and timelines.
- **Not handled:** 7z, rar and zstd archives; ext4 file *contents* of deleted files (use dedicated carving tools).

## Security

- Crumbs has **no authentication**. It binds to `127.0.0.1` by default; do not expose it on a network without
  putting something with authentication in front of it.
- Evidence is only ever read. The database and the archive extraction folder are written next to the database
  path you choose.
- Nothing leaves your machine except intel lookups you trigger. API keys are stored **unencrypted** in the case
  database, so treat the `.db` file as sensitive.

## Third-party components

- [Cytoscape.js](https://js.cytoscape.org/) (MIT), bundled in `static/vendor/` so the dashboard works offline.
- Optional data you supply: DB-IP (CC BY 4.0) or MaxMind GeoLite2 databases; VirusTotal, Shodan and AbuseIPDB
  under their own terms.
