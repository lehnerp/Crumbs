"""
Whole-filesystem sweep for a full Debian dump (any release: stretch, buster, bullseye, bookworm).

An intruder who deletes files and resets timestamps removes the obvious evidence but leaves the
metadata inconsistent with itself. This module reads dpkg's own records out of the dump and checks
every file, folder, link and device node against them:

  Timestamps that were changed
    fs_backdated_package_file  content differs from the package, yet the modified time is older than the
                               moment dpkg installed that package (dpkg always writes a fresh copy, so an
                               edited file must be newer) -> the timestamp was set back
    fs_copied_timestamp        an added/changed system file carries exactly the time of a neighbouring
                               package file (touch -r /bin/ls /usr/bin/evil)
    fs_touch_style_mtime       whole-second time on a locally written file where its neighbours have
                               sub-seconds (touch -d / touch -t write .000000000)
    fs_predates_install        unpackaged file in a system folder dated before the OS was installed
    fs_mtime_after_ctime / fs_ctime_reveals_change   only when inode change times survived collection
    fs_born_after_modified     birth time after modified time (needs a Sleuth Kit bodyfile)

  Things that were deleted
    fs_referenced_missing      a path used in shell history / auditd / sudo / cron that is no longer on disk
    fs_expected_log_missing    a log the rsyslog configuration writes to (or wtmp/btmp/lastlog) is gone
    fs_tool_deleted            inspection or logging programs removed (last, w, ps, ss, auditd, rsyslogd ...)
    fs_package_files_missing   other files a package installed that are gone
    fs_entry_removed           folder changed after everything it still holds (entry deleted / renamed out)
    fs_orphan_owner            files owned by a user or group that no longer exists (account deleted)
    fs_package_removed / fs_security_package_removed   dpkg status-old vs status, dpkg.log remove/purge
    fs_deleted_entry           deleted names recorded in a Sleuth Kit bodyfile (fls -r -m)

  Hidden or misplaced
    fs_hidden_system_entry, fs_misplaced_node, fs_unowned_module, fs_exec_in_temp, fs_history_to_null

It also writes a generated, searchable "[crumbs]/filesystem-timeline.txt": one line per changed, added or
removed item, in UTC. Because episodes tag lines by time, the filesystem changes inside an episode window
show up there automatically, and `ep:N` search returns them.

Collection fidelity is measured, not assumed: inode change (ctime) and access times are usually reset by
copying the evidence, so checks that need them run only when they look original.
"""
import json
import os
import re
from collections import Counter, defaultdict

import analyzers as az
import linux

RULES = {
    "fs_backdated_package_file": ("high", "timestomp", "Changed from its Debian package, but its timestamp is older than the package install (set back to hide the change)"),
    "fs_copied_timestamp": ("high", "timestomp", "Added or changed system file carries the exact timestamp of a neighbouring package file (touch -r)"),
    "fs_touch_style_mtime": ("medium", "timestomp", "Whole-second timestamp where neighbouring files have sub-seconds (set with touch)"),
    "fs_predates_install": ("medium", "timestomp", "Unpackaged file in a system folder dated before this system was installed"),
    "fs_mtime_after_ctime": ("high", "timestomp", "Modified time later than the inode change time (only possible by manipulating time)"),
    "fs_ctime_reveals_change": ("high", "timestomp", "Inode change time long after the modified time on an added or changed system file"),
    "fs_born_after_modified": ("high", "timestomp", "File created after its own modified time (bodyfile birth time): timestamp set back"),
    "fs_referenced_missing": ("high", "deletion", "Path used in a command no longer exists (deleted after use)"),
    "fs_referenced_gone": ("medium", "deletion", "Path mentioned in logs or history no longer exists"),
    "fs_expected_log_missing": ("high", "deletion", "Log file the logging configuration writes to is missing"),
    "fs_tool_deleted": ("high", "defense_evasion", "Inspection or logging program removed from disk"),
    "fs_package_files_missing": ("medium", "deletion", "Files a package installed are missing from disk"),
    "fs_entry_removed": ("medium", "deletion", "Folder changed after everything it still holds: an entry was deleted or renamed out"),
    "fs_orphan_owner": ("high", "deletion", "Files owned by a user or group that no longer exists (account deleted)"),
    "fs_package_removed": ("low", "deletion", "Package removed from the system"),
    "fs_security_package_removed": ("high", "defense_evasion", "Security, audit or logging package removed"),
    "fs_unowned_module": ("high", "rootkit", "Kernel module not installed by any package"),
    "fs_hidden_system_entry": ("medium", "hiding", "Hidden or deceptively named entry in a system folder"),
    "fs_misplaced_node": ("high", "hiding", "Regular file inside /dev, or device node outside /dev"),
    "fs_exec_in_temp": ("high", "execution", "Program (ELF) stored in a temporary, web or hidden folder"),
    "fs_deleted_entry": ("medium", "deletion", "Deleted file recorded in the disk image (bodyfile)"),
    "fs_history_to_null": ("high", "log_tampering", "History or log file replaced by a link to /dev/null"),
}
for _rid, (_sev, _cat, _desc) in RULES.items():
    az.RULE_INFO[_rid] = {"severity": _sev, "category": _cat, "description": _desc}

TIMELINE_REL = "[crumbs]/filesystem-timeline.txt"

# where changes matter (relative to the system root)
INTEREST = re.compile(r"^(tmp|var/tmp|dev|run|root|home|var/www|srv|opt|usr/local|etc|var/spool|var/log|var/mail|"
                      r"boot|bin|sbin|lib|lib32|lib64|usr/bin|usr/sbin|usr/lib|usr/libexec|usr/games|var/backups|"
                      r"var/lib/(?!apt|dpkg|ucf|mlocate|aptitude|man-db|systemd/deb-systemd|dhcp|python|polkit))(/|$)")
NOISE = re.compile(r"^(var/cache|var/lib/apt|var/lib/dpkg/(?!status)|usr/share/(doc|man|locale|info|icons|mime|fonts|"
                   r"lintian|zoneinfo|i18n)|proc|sys)(/|$)|/__pycache__/|\.pyc$")
SYSTEM_BIN = re.compile(r"^(bin|sbin|lib|lib32|lib64|libx32|usr/bin|usr/sbin|usr/lib|usr/libexec|boot)(/|$)")
SUSPICIOUS_LOC = re.compile(r"^(tmp|var/tmp|dev/shm|run/shm|var/www|srv|var/spool|var/mail)(/|$)|(^|/)\.[^/]")
DOC_PATH = re.compile(r"^usr/share/(doc|man|locale|info|lintian|help)/")
KNOWN_DOT = {".placeholder", ".keep", ".gitkeep", ".gitignore", ".htaccess", ".well-known", ".pwd.lock", ".updated",
             ".X11-unix", ".ICE-unix", ".font-unix", ".XIM-unix", ".Test-unix", ".java", ".etckeeper", ".git",
             ".build-id", ".dwz", ".debug", ".hmac", ".depmod", ".lock", ".gnupg", ".cache", ".config", ".local"}
TOOLS = {"usr/bin/last": "last", "usr/bin/lastb": "lastb", "usr/bin/lastlog": "lastlog", "usr/bin/w": "w",
         "usr/bin/w.procps": "w", "usr/bin/who": "who", "bin/ps": "ps", "usr/bin/ps": "ps", "usr/bin/top": "top",
         "bin/netstat": "netstat", "usr/bin/netstat": "netstat", "bin/ss": "ss", "usr/bin/ss": "ss",
         "usr/bin/lsof": "lsof", "usr/bin/strace": "strace", "usr/sbin/tcpdump": "tcpdump", "sbin/auditctl": "auditctl",
         "sbin/auditd": "auditd", "usr/sbin/auditd": "auditd", "usr/sbin/rsyslogd": "rsyslogd",
         "bin/journalctl": "journalctl", "usr/bin/journalctl": "journalctl", "usr/bin/find": "find",
         "bin/lsattr": "lsattr", "usr/bin/lsattr": "lsattr", "bin/chattr": "chattr", "usr/bin/chattr": "chattr",
         "usr/bin/md5sum": "md5sum", "usr/bin/sha256sum": "sha256sum", "usr/bin/debsums": "debsums",
         "sbin/iptables": "iptables", "usr/sbin/iptables": "iptables", "usr/bin/history": "history",
         "usr/sbin/logrotate": "logrotate", "usr/bin/pstree": "pstree", "bin/kmod": "kmod (lsmod)",
         "usr/bin/dmesg": "dmesg", "bin/dmesg": "dmesg", "usr/sbin/rkhunter": "rkhunter",
         "usr/sbin/chkrootkit": "chkrootkit", "usr/bin/aide": "aide"}
SECURITY_PKGS = {"auditd", "rsyslog", "syslog-ng", "logrotate", "aide", "tripwire", "rkhunter", "chkrootkit", "fail2ban",
                 "apparmor", "ufw", "iptables", "iptables-persistent", "debsums", "sysstat", "acct", "tiger", "lynis",
                 "clamav", "clamav-daemon", "osquery", "auditbeat", "filebeat", "wazuh-agent", "ossec-hids-agent",
                 "samhain", "logwatch", "psad", "snort", "suricata", "procps", "net-tools", "lsof", "strace", "tcpdump"}
R_ABS = re.compile(r"(?<![\w./~-])(/(?:tmp|var|dev/shm|etc|usr|opt|root|home|srv|lib|lib64|bin|sbin|boot|mnt|media)"
                   r"(?:/[^\s'\"`;|&<>(){}\[\],=]+)+)")
R_DEL_CMD = re.compile(r"\b(rm|shred|srm|unlink|wipe|truncate|mv)\b")


def _ns(ts):
    """'YYYY-MM-DD HH:MM:SS' (UTC) -> epoch ns."""
    import calendar
    import time
    try:
        return calendar.timegm(time.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")) * 10**9 if ts else None
    except ValueError:
        return None


def _ts(ns):
    return az.epoch_to_ts(ns / 1e9) if ns else None


def _dur(sec):
    sec = int(abs(sec))
    for unit, n in (("day", 86400), ("h", 3600), ("min", 60)):
        if sec >= n:
            v = sec // n
            return f"{v} {unit}{'s' if unit == 'day' and v != 1 else ''}"
    return f"{sec} s"


def system_prefix(files):
    """Relative prefix of a full Debian root inside the evidence folder ('' if the folder is the root),
    or None when this is not a filesystem dump (just collected logs)."""
    rels = {f["rel"] for f in files}
    for r in rels:
        if r.endswith("var/lib/dpkg/status"):
            pre = r[: -len("var/lib/dpkg/status")]
            if pre + "etc/passwd" in rels and any(x.startswith(pre + "usr/") for x in rels):
                return pre
    return None


def _aliases(root, pre):
    """Merged-/usr: top-level bin, sbin, lib... may be links into usr/."""
    out = {}
    for d in ("bin", "sbin", "lib", "lib32", "lib64", "libx32"):
        p = os.path.join(root, pre, d)
        if os.path.islink(p):
            t = os.readlink(p).strip("/")
            if t.startswith("usr/"):
                out[pre + d + "/"] = pre + t + "/"
    return out


def _resolve(rel, al):
    for a, t in al.items():
        if rel.startswith(a):
            return t + rel[len(a):]
    return rel


def dpkg_md5_map(root, found):
    """Called while indexing: {rel: md5} for every file dpkg recorded a checksum for (used to skip
    line-indexing of files that are byte-identical to their package)."""
    out = {}
    for p in found:
        if "/var/lib/dpkg/info/" in p.replace(os.sep, "/") and p.endswith(".md5sums"):
            base = p.replace(os.sep, "/").split("var/lib/dpkg/info/")[0]
            pre = os.path.relpath(base, root).replace(os.sep, "/")
            pre = "" if pre == "." else pre.rstrip("/") + "/"
            al = _aliases(root, pre)
            try:
                with open(p, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        parts = line.strip().split(None, 1)
                        if len(parts) == 2 and len(parts[0]) == 32:
                            out[_resolve(pre + parts[1].lstrip("/"), al)] = parts[0]
            except OSError:
                pass
    return out


def _read(root, rel, limit=20_000_000):
    try:
        with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def _dense_window(values, width_ns):
    """Largest share of values falling inside any window of the given width, and its midpoint."""
    v = sorted(x for x in values if x)
    if len(v) < 20:
        return 0.0, None
    best, j, mid = 0, 0, None
    for i in range(len(v)):
        while v[i] - v[j] > width_ns:
            j += 1
        if i - j + 1 > best:
            best, mid = i - j + 1, (v[i] + v[j]) // 2
    return best / len(v), mid


def analyze(con, files, root):
    pre = system_prefix(files)
    if pre is None:
        return []
    out = []
    tl = []        # timeline entries: (ns, flag, path, info, key)
    notes = []
    al = _aliases(root, pre)
    P = lambda rel: "/" + rel[len(pre):] if rel.startswith(pre) else "/" + rel    # display path
    R = lambda rel: rel[len(pre):] if rel.startswith(pre) else rel                 # rel inside the system root

    by_rel = {f["rel"]: f for f in files}
    nodes = [dict(r) for r in con.execute("SELECT rel, type, target, mode, uid, gid, mtime_ns, ctime_ns FROM fsnodes")]
    dirs = [dict(r) for r in con.execute("SELECT rel, mtime_ns, ctime_ns, birth_ns, entries FROM dirs")]
    present = set(by_rel) | {n["rel"] for n in nodes} | {d["rel"] for d in dirs}

    # ---------------------------------------------------------------- dpkg records, read from the dump
    expected, owned, owner, list_ns, conffiles = {}, set(), {}, {}, {}
    info_dir = pre + "var/lib/dpkg/info/"
    for rel, f in by_rel.items():
        if not rel.startswith(info_dir):
            continue
        name = rel[len(info_dir):]
        if name.endswith(".list"):
            pkg = name[:-5].split(":")[0]
            list_ns[pkg] = f["mtime_ns"]
            for line in _read(root, rel).splitlines():
                p = line.strip().lstrip("/")
                if p and p != ".":
                    r = _resolve(pre + p, al)
                    owned.add(r)
                    owner.setdefault(r, pkg)
        elif name.endswith(".md5sums"):
            pkg = name[:-8].split(":")[0]
            for line in _read(root, rel).splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2 and len(parts[0]) == 32:
                    r = _resolve(pre + parts[1].lstrip("/"), al)
                    expected[r] = (parts[0], pkg)
                    owned.add(r)
                    owner.setdefault(r, pkg)
    status_txt = _read(root, pre + "var/lib/dpkg/status")
    installed = _dpkg_installed(status_txt)
    pkg = None
    for line in status_txt.splitlines():
        if line.startswith("Package: "):
            pkg = line[9:].strip()
        m = re.match(r"^ (/\S+) ([0-9a-f]{32})", line)
        if m and pkg:
            r = _resolve(pre + m.group(1).lstrip("/"), al)
            conffiles[r] = (m.group(2), pkg)
            owned.add(r)
            owner.setdefault(r, pkg)

    real_installs = sorted(v for v in list_ns.values() if v and v > 946684800 * 10**9)
    os_install = real_installs[0] if real_installs else None
    osrel = dict(re.findall(r'^(\w+)="?([^"\n]*)"?', _read(root, pre + "etc/os-release"), re.M))
    os_name = osrel.get("PRETTY_NAME") or ("Debian " + _read(root, pre + "etc/debian_version").strip())

    # users and groups that exist now
    users, groups = {}, set()
    for line in _read(root, pre + "etc/passwd").splitlines():
        p = line.split(":")
        if len(p) >= 4 and p[2].isdigit():
            users[int(p[2])] = p[0]
    for line in _read(root, pre + "etc/group").splitlines():
        p = line.split(":")
        if len(p) >= 3 and p[2].isdigit():
            groups.add(int(p[2]))

    # ---------------------------------------------------------------- collection fidelity
    sysfiles = [f for f in files if f["rel"].startswith(pre)]
    c_share, copy_mid = _dense_window([f["ctime_ns"] for f in sysfiles], 2 * 3600 * 10**9)
    a_share, _ = _dense_window([f["atime_ns"] for f in sysfiles], 2 * 3600 * 10**9)
    ctime_ok = bool(sysfiles) and c_share < 0.85 and any(f["ctime_ns"] for f in sysfiles)
    atime_ok = bool(sysfiles) and a_share < 0.85
    unowned_files = [f for f in sysfiles if _resolve(f["rel"], al) not in owned and not NOISE.search(R(f["rel"]))
                     and f["mtime_ns"]]
    ns_share = (sum(1 for f in unowned_files if f["mtime_ns"] % 10**9) / len(unowned_files)) if unowned_files else 0
    exp_files = [r for r in expected if not DOC_PATH.match(R(r))]
    have = sum(1 for r in exp_files if r in present)
    coverage = have / len(exp_files) if exp_files else 0
    core = lambda *xs: any(_resolve(pre + x, al) in present for x in xs)
    complete = coverage >= 0.6 and core("bin/ls", "usr/bin/ls") and core("bin/sh", "bin/bash", "usr/bin/bash", "bin/dash") \
        and core("lib/x86_64-linux-gnu", "usr/lib/x86_64-linux-gnu", "lib/i386-linux-gnu", "lib/aarch64-linux-gnu",
                 "usr/lib/aarch64-linux-gnu", "lib") and len(exp_files) >= 10
    if not ctime_ok:
        notes.append(f"Inode change times (ctime): {round(c_share * 100)}% fall inside one 2-hour window around "
                     f"{_ts(copy_mid)} UTC, so they record when the evidence was copied, not original activity. "
                     "Checks that need ctime were skipped; modified times (mtime) are used instead.")
    if not complete:
        notes.append(f"This looks like a partial collection ({round(coverage * 100)}% of {len(exp_files)} package files "
                     "present, core system files absent), so missing files are not treated as deletions and "
                     "folder-deletion checks were skipped.")

    def is_owned(rel):
        return _resolve(rel, al) in owned

    def who(uid):
        return users.get(uid, f"UID {uid}") if uid is not None else "?"

    def status_of(f):
        r = _resolve(f["rel"], al)
        e = expected.get(r) or conffiles.get(r)
        if e:
            return ("changed from " + e[1]) if f["md5"] and f["md5"] != e[0] else ("from " + e[1])
        return ("in package " + owner[r]) if r in owner else "not from any package"

    # ---------------------------------------------------------------- commands (history, auditd, sudo, cron)
    cmd_lines = []
    for f in files:
        rel = f["rel"]
        k = linux.path_kind(rel)
        if re.search(r"(^|/)\.\w*_?history$", rel) or k in ("audit_log", "auth_log", "cron"):
            hist = k != "auth_log"
            for row in con.execute("SELECT line_no, ts, text FROM lines WHERE file_id=?", (f["id"],)):
                t = row["text"] or ""
                if hist or "COMMAND=" in t or "CMD" in t:
                    cmd_lines.append((f["id"], rel, hist, row["line_no"], row["ts"], t))
    touched = {}    # display path -> (ts, file id, line, command): who set this file's time, and when
    for fid, rel, _h, ln, ts, t in cmd_lines:
        if not re.search(r"\btouch\b[^|;&]*\s(-\w*[dtr]|--date|--reference)", t):
            continue
        ref = re.search(r"(?:-\w*r\s+|--reference[= ])(\S+)", t)
        for m in R_ABS.finditer(t[t.find("touch"):]):
            path = m.group(1).rstrip(".:'\")")
            if ref and path == ref.group(1).strip("'\""):
                continue
            touched.setdefault(path, (ts, fid, ln, t.strip()[:200], ref.group(1) if ref else None))

    def touch_note(rel):
        x = touched.get(P(rel))
        return (f" The command '{x[3]}' ({P(by_id[x[1]]['rel']) if x[1] in by_id else '?'} line {x[2]}, "
                f"{x[0] or 'time unknown'}) did it.") if x else ""

    def touch_ts(rel, default=None):
        x = touched.get(P(rel))
        return x[0] if x and x[0] else default

    by_id = {f["id"]: f for f in files}

    # ---------------------------------------------------------------- 1. backdated package files
    backdated = set()
    for rel, f in by_rel.items():
        r = _resolve(rel, al)
        e, is_conf = expected.get(r), False
        if r in conffiles:
            e, is_conf = conffiles[r], True
        if not e or not f["md5"] or f["md5"] == e[0] or not f["mtime_ns"]:
            continue
        # dpkg replaces non-conffiles on every upgrade, so their own package's install time is the floor;
        # an edited conffile can legitimately survive an upgrade, so for those only the OS install counts.
        floor = os_install if is_conf else list_ns.get(e[1])
        if floor and f["mtime_ns"] < floor - 60 * 10**9:
            backdated.add(rel)
            real = f["ctime_ns"] if ctime_ok and f["ctime_ns"] and f["ctime_ns"] > floor else None
            out.append(("fs_backdated_package_file", f["id"], None, _ts(real) if real else touch_ts(rel), None,
                        f"{P(rel)} differs from what {e[1]} installed{' (configuration file)' if is_conf else ''}, "
                        f"but claims to be last modified {_ts(f['mtime_ns'])} UTC, "
                        f"{_dur((floor - f['mtime_ns']) / 1e9)} before {'this system was installed' if is_conf else 'that package was installed'} "
                        f"({_ts(floor)}). The content was replaced and the timestamp set back"
                        + (f"; the inode change time {_ts(real)} UTC shows when it really happened." if real else ".")
                        + touch_note(rel),
                        json.dumps({"package": e[1], "claimed": _ts(f["mtime_ns"]), "installed": _ts(floor)})))

    # ---------------------------------------------------------------- 2. copied / touch-style / pre-install times
    owned_times = defaultdict(dict)    # dir -> {mtime_ns: package file}
    for rel, f in by_rel.items():
        if rel in expected or _resolve(rel, al) in expected:
            if f["mtime_ns"] and f["md5"] == (expected.get(_resolve(rel, al)) or ("",))[0]:
                owned_times[rel.rsplit("/", 1)[0]].setdefault(f["mtime_ns"], rel)
    dir_ns = defaultdict(lambda: [0, 0])   # dir -> [with sub-seconds, total] among unowned files
    for f in unowned_files:
        d = f["rel"].rsplit("/", 1)[0]
        dir_ns[d][1] += 1
        if f["mtime_ns"] % 10**9:
            dir_ns[d][0] += 1
    for f in sysfiles:
        rel = f["rel"]
        r = R(rel)
        if not f["mtime_ns"] or NOISE.search(r) or rel.startswith(info_dir):
            continue
        own = is_owned(rel)
        changed = rel in backdated or (not own and SYSTEM_BIN.match(r))
        d = rel.rsplit("/", 1)[0]
        if changed and not own:
            twin = owned_times.get(d, {}).get(f["mtime_ns"])
            x = touched.get(P(rel))
            if x and x[4]:
                ref = _resolve(pre + x[4].lstrip("/"), al)
                if by_rel.get(ref) and by_rel[ref]["mtime_ns"] == f["mtime_ns"]:
                    twin = ref         # the reference the command actually named
            if twin and twin != rel:
                out.append(("fs_copied_timestamp", f["id"], None, touch_ts(rel), None,
                            f"{P(rel)} is not from any package, yet its modified time {_ts(f['mtime_ns'])} UTC is "
                            f"identical to the package file {P(twin)} next to it: the time was copied (touch -r) "
                            "so it blends in." + touch_note(rel), json.dumps({"twin": P(twin)})))
                continue
            if os_install and f["mtime_ns"] < os_install - 86400 * 10**9 and not r.startswith("usr/local/"):
                out.append(("fs_predates_install", f["id"], None, None, None,
                            f"{P(rel)} is not from any package but is dated {_ts(f['mtime_ns'])} UTC, "
                            f"{_dur((os_install - f['mtime_ns']) / 1e9)} before this system was installed "
                            f"({_ts(os_install)}).", None))
                continue
        if not own and ns_share >= 0.5 and f["mtime_ns"] % 10**9 == 0 and INTEREST.match(r):
            w, t = dir_ns[d]
            if t - 1 >= 2 and w / max(1, t - 1) >= 0.6:
                minute = " and exactly on the minute" if (f["mtime_ns"] // 10**9) % 60 == 0 else ""
                out.append(("fs_touch_style_mtime", f["id"], None, touch_ts(rel, _ts(f["mtime_ns"])), None,
                            f"{P(rel)} modified {_ts(f['mtime_ns'])} UTC with zero sub-seconds{minute}, while "
                            f"{w} of the other {t - 1} local files in that folder have sub-second times: "
                            "typical of a time written with touch." + touch_note(rel), None))
        if ctime_ok and f["ctime_ns"]:
            if f["mtime_ns"] - f["ctime_ns"] > 2 * 10**9:
                out.append(("fs_mtime_after_ctime", f["id"], None, _ts(f["ctime_ns"]), None,
                            f"{P(rel)}: modified {_ts(f['mtime_ns'])} but inode changed {_ts(f['ctime_ns'])} UTC. "
                            "Setting a time always updates the inode change time, so the modified time was forged "
                            "or the clock was changed.", None))
            elif changed and (f["ctime_ns"] - f["mtime_ns"]) > 86400 * 10**9:
                out.append(("fs_ctime_reveals_change", f["id"], None, _ts(f["ctime_ns"]), None,
                            f"{P(rel)} ({status_of(f)}) claims {_ts(f['mtime_ns'])}, but its inode changed "
                            f"{_ts(f['ctime_ns'])} UTC, {_dur((f['ctime_ns'] - f['mtime_ns']) / 1e9)} later.", None))

    # ---------------------------------------------------------------- 3. deleted: referenced in commands
    seen = {}
    for fid, rel, hist, line_no, ts, t in cmd_lines:
        row = {"line_no": line_no, "ts": ts}
        if True:
            for m in R_ABS.finditer(t):
                path = m.group(1).rstrip(".:'\")")
                if any(c in path for c in "*?$%~{") or path.startswith(("/var/run/", "/run/", "/var/lock/", "/dev/")) \
                        and not path.startswith("/dev/shm/"):
                    continue
                r = _resolve(pre + path.lstrip("/"), al)
                if r in present or r.rstrip("/") in present:
                    continue
                key = path
                deleted = bool(R_DEL_CMD.search(t[:m.start()]))
                if key not in seen or (deleted and not seen[key]["deleted"]):
                    seen[key] = {"fid": fid, "line": row["line_no"], "ts": row["ts"], "src": rel,
                                 "text": t.strip()[:240], "deleted": deleted, "hist": hist}
    for path, s in sorted(seen.items(), key=lambda x: (x[1]["ts"] or "9", x[0]))[:400]:
        susp = bool(SUSPICIOUS_LOC.search(path.lstrip("/"))) or s["deleted"]
        if not susp and (not s["hist"] or not complete):
            continue
        how = "removed by the command itself" if s["deleted"] else \
            "no longer on disk" if complete else "not in the collected evidence (deleted, or not collected)"
        if not complete and not s["deleted"]:
            susp = False
        out.append(("fs_referenced_missing" if susp else "fs_referenced_gone", s["fid"], s["line"], s["ts"], None,
                    f"{path} was used in {P(s['src'])} ({s['text'][:160]}) and is {how}.",
                    json.dumps({"path": path, "deleted_by_command": s["deleted"]})))
        tl.append((_ns(s["ts"]), "R", path, f"used in {P(s['src'])} line {s['line']}; {how}", None))

    # ---------------------------------------------------------------- 4. deleted: logs, tools, package files
    logcfg = _read(root, pre + "etc/rsyslog.conf") + "\n" + "\n".join(
        _read(root, r) for r in by_rel if r.startswith(pre + "etc/rsyslog.d/") and r.endswith(".conf"))
    targets = set(re.findall(r"^\s*[^#\s$][^\s]*\s+-?(/var/log/[^\s;]+)", logcfg, re.M))
    targets |= set(re.findall(r'file="(/var/log/[^"]+)"', logcfg))
    targets |= {"/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog"}
    logdir = next((d for d in dirs if d["rel"] == pre + "var/log"), None)
    for t in sorted(targets):
        r = pre + t.lstrip("/")
        if r in present or any(x.startswith(r + ".") for x in present if x.startswith(pre + "var/log/")):
            continue
        why = "rsyslog writes to it" if t not in ("/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog") else \
            "login accounting always keeps it"
        out.append(("fs_expected_log_missing", None, None, _ts(logdir["mtime_ns"]) if logdir else None, None,
                    f"{t} is missing (and has no rotated copies) although {why}"
                    + (f"; /var/log itself last changed {_ts(logdir['mtime_ns'])} UTC" if logdir else "") + ".", None))
        tl.append((logdir["mtime_ns"] if logdir else None, "X", t, f"log file missing although {why}", None))

    if complete:
        missing_by_pkg = defaultdict(list)
        for r, (_md5, pkgname) in expected.items():
            if r in present or DOC_PATH.match(R(r)):
                continue
            tool = TOOLS.get(R(r))
            if tool:
                d = by_rel.get(r.rsplit("/", 1)[0]) or next((x for x in dirs if x["rel"] == r.rsplit("/", 1)[0]), None)
                when = _ts(d["mtime_ns"]) if d else None
                out.append(("fs_tool_deleted", None, None, when, None,
                            f"{P(r)} ({tool}, from {pkgname}) is gone although the package is still installed"
                            + (f"; its folder last changed {when} UTC" if when else "") + ".", None))
                tl.append((d["mtime_ns"] if d else None, "X", P(r), f"{tool} removed (package {pkgname} still installed)", None))
            elif re.match(r"(bin|sbin|lib|lib64|usr/bin|usr/sbin|usr/lib|etc|boot)/", R(r)):
                missing_by_pkg[pkgname].append(P(r))
        for pkgname, lst in sorted(missing_by_pkg.items(), key=lambda x: -len(x[1]))[:80]:
            out.append(("fs_package_files_missing", None, None, None, None,
                        f"{len(lst)} file(s) installed by {pkgname} are missing: {', '.join(lst[:6])}"
                        f"{' …' if len(lst) > 6 else ''}", json.dumps(lst[:200])))

    # removed packages: status-old vs status, and dpkg.log
    old = _dpkg_installed(_read(root, pre + "var/lib/dpkg/status-old"))
    gone = sorted(set(old) - set(installed))
    logged = set()
    for row in con.execute("SELECT l.file_id, l.line_no, l.ts, l.text FROM lines l JOIN files f ON f.id = l.file_id "
                           "WHERE f.rel LIKE ? AND (l.text LIKE '% remove %' OR l.text LIKE '% purge %')",
                           (pre + "var/log/dpkg.log%",)):
        m = re.search(r"\s(remove|purge)\s+([\w.+-]+)(?::\w+)?\s", row["text"] or "")
        if not m:
            continue
        name = m.group(2)
        if (name, m.group(1)) in logged:
            continue
        logged.add((name, m.group(1)))
        rule = "fs_security_package_removed" if name in SECURITY_PKGS else "fs_package_removed"
        out.append((rule, row["file_id"], row["line_no"], row["ts"], None, f"package {name} was {m.group(1)}d ({row['text'].strip()[:160]})", None))
    for name in gone:
        if any(n == name for n, _a in logged):
            continue
        rule = "fs_security_package_removed" if name in SECURITY_PKGS else "fs_package_removed"
        st = by_rel.get(pre + "var/lib/dpkg/status")
        out.append((rule, st["id"] if st else None, None, _ts(st["mtime_ns"]) if st else None, None,
                    f"package {name} {old[name]} is in dpkg's previous status (status-old) but no longer installed", None))

    # ---------------------------------------------------------------- 5. deleted: folders that lost entries
    if complete:
        newest = defaultdict(int)
        for f in sysfiles:
            d = f["rel"].rsplit("/", 1)[0]
            t = max(f["mtime_ns"] or 0, (f["ctime_ns"] or 0) if ctime_ok else 0)
            pk = owner.get(_resolve(f["rel"], al))
            if pk and list_ns.get(pk):
                t = max(t, list_ns[pk])          # dpkg created it when the package was installed
            newest[d] = max(newest[d], t)
        # moments when dpkg itself was writing (installs, upgrades, removals)
        pkg_events = sorted(set(v for v in list_ns.values() if v) | {
            _ns(r[0]) for r in con.execute("SELECT l.ts FROM lines l JOIN files f ON f.id = l.file_id WHERE "
                                           "f.rel LIKE ? AND l.ts IS NOT NULL", (pre + "var/log/dpkg.log%",)) if r[0]}
            | {f["mtime_ns"] for f in sysfiles if f["rel"] in (pre + "var/lib/dpkg/status", pre + "var/lib/dpkg/status-old")})
        import bisect

        def dpkg_explains(ns):
            i = bisect.bisect_left(pkg_events, ns - 2 * 60 * 10**9)
            return i < len(pkg_events) and pkg_events[i] <= ns + 15 * 60 * 10**9
        for n in nodes:
            d = n["rel"].rsplit("/", 1)[0]
            newest[d] = max(newest[d], n["mtime_ns"] or 0)
        for d in dirs:
            parent = d["rel"].rsplit("/", 1)[0] if "/" in d["rel"] else ""
            newest[parent] = max(newest[parent], d["mtime_ns"] or 0)
        cand, copied_dirs = [], 0
        for d in dirs:
            r = R(d["rel"])
            if not d["rel"].startswith(pre) or not d["mtime_ns"] or NOISE.search(r) or not INTEREST.match(r):
                continue
            if copy_mid and not ctime_ok and abs(d["mtime_ns"] - copy_mid) < 3 * 3600 * 10**9:
                copied_dirs += 1
                continue
            if not d["entries"]:
                base = d["rel"].rsplit("/", 1)[-1]
                if base in KNOWN_DOT or not SUSPICIOUS_LOC.search(r) or not os_install or \
                        d["mtime_ns"] < os_install + 86400 * 10**9:
                    continue
            gap = (d["mtime_ns"] - newest.get(d["rel"], 0)) / 1e9
            if gap > 600 and not (is_owned(d["rel"]) and dpkg_explains(d["mtime_ns"])):
                cand.append((d, gap))
        sys_dirs = [d for d in dirs if d["rel"].startswith(pre) and INTEREST.match(R(d["rel"]))]
        if copied_dirs:
            notes.append(f"{copied_dirs} folder times equal the copy time and were ignored for deletion checks.")
        if sys_dirs and len(cand) > 0.6 * len(sys_dirs) and len(sys_dirs) > 10:
            notes.append("Most folders are newer than everything inside them: folder times were reset by the copy, "
                         "so folder-based deletion times were not used.")
        else:
            for d, gap in sorted(cand, key=lambda x: -x[0]["mtime_ns"])[:300]:
                if not d["entries"]:
                    txt = f"{P(d['rel'])}/ is now empty and last changed {_ts(d['mtime_ns'])} UTC: its contents were removed then."
                    what = "now empty"
                else:
                    what = f"{d['entries']} entries remain"
                    txt = (f"{P(d['rel'])}/ changed {_ts(d['mtime_ns'])} UTC, {_dur(gap)} after the newest item it "
                           f"still holds ({what}): something was deleted or renamed out of it then.")
                out.append(("fs_entry_removed", None, None, _ts(d["mtime_ns"]), None, txt, None))
                tl.append((d["mtime_ns"], "D", P(d["rel"]) + "/", f"entry deleted or renamed out ({what})", None))

    # ---------------------------------------------------------------- 6. orphaned owners
    if users and any(f["uid"] is not None for f in sysfiles):
        by_uid = defaultdict(list)
        runtime = lambda rel: R(rel).startswith(("run/", "dev/", "var/run/", "var/lock/"))
        for f in sysfiles:
            if f["uid"] is not None and f["uid"] not in users and not runtime(f["rel"]):
                by_uid[f["uid"]].append(f)
        for n in nodes:
            if n["rel"].startswith(pre) and n["uid"] is not None and n["uid"] not in users and not runtime(n["rel"]):
                by_uid[n["uid"]].append({"id": None, "rel": n["rel"], "mtime_ns": n["mtime_ns"]})
        if any(len(v) > 0.5 * len(sysfiles) for v in by_uid.values()):
            notes.append("Most files are owned by an account that does not exist in this system's passwd: "
                         "ownership was not preserved when the evidence was copied, so orphan-owner checks were skipped.")
        else:
            for uid, fl in sorted(by_uid.items()):
                fl.sort(key=lambda x: x["mtime_ns"] or 0)
                last = fl[-1]
                out.append(("fs_orphan_owner", last["id"], None, _ts(fl[0]["mtime_ns"]), _ts(last["mtime_ns"]),
                            f"{len(fl)} item(s) owned by UID {uid}, which no longer exists in /etc/passwd "
                            f"(account deleted after creating them), e.g. {', '.join(P(x['rel']) for x in fl[-5:])}; "
                            f"dated {_ts(fl[0]['mtime_ns'])} to {_ts(last['mtime_ns'])} UTC",
                            json.dumps([P(x["rel"]) for x in fl[:300]])))

    # ---------------------------------------------------------------- 7. hidden, misplaced, modules, programs
    hidden = defaultdict(list)
    all_items = [(f["rel"], f) for f in sysfiles] + [(n["rel"], None) for n in nodes if n["rel"].startswith(pre)]
    for rel, f in all_items:
        r = R(rel)
        parts = r.split("/")
        if re.search(r"/(site-packages|dist-packages|node_modules|vendor|gems)/", "/" + r) and \
                not (f and "ELF" in (f["magic"] or "")):
            continue
        for i, comp in enumerate(parts):
            if comp in KNOWN_DOT:
                break                               # e.g. /etc/.java/... : the whole subtree is ordinary
            odd = comp in ("...", "..", " ", ". ", ".. ") or comp != comp.strip() or any(ord(c) < 32 for c in comp)
            dot = comp.startswith(".") and not comp.endswith(".hmac")
            top = parts[0]
            sysloc = top in ("bin", "sbin", "lib", "lib32", "lib64", "boot", "dev", "usr", "tmp", "var", "srv", "opt") \
                or (top == "etc" and parts[1:2] != ["skel"])
            if (odd or (dot and sysloc)) and not is_owned(rel) and not r.startswith(("var/lib/", "var/cache/")):
                hidden["/".join(parts[: i + 1])].append((rel, f))
                break
    for h, items in sorted(hidden.items())[:200]:
        elf = [x for x in items if x[1] and "ELF" in (x[1]["magic"] or "")]
        execs = [x for x in items if x[1] and (x[1]["mode"] or 0) & 0o111]
        newest_f = max((x[1] for x in items if x[1]), key=lambda f: f["mtime_ns"] or 0, default=None)
        out.append(("fs_hidden_system_entry", (elf[0][1] if elf else newest_f or {}).get("id"), None,
                    _ts(newest_f["mtime_ns"]) if newest_f else None, None,
                    f"hidden entry /{h} ({len(items)} item(s){', ' + str(len(elf)) + ' program(s)' if elf else ''}"
                    f"{', executable' if execs and not elf else ''}): "
                    + ", ".join(P(x[0]) for x in items[:4]), json.dumps([P(x[0]) for x in items[:100]])))
    for n in nodes:
        r = R(n["rel"])
        if n["rel"].startswith(pre) and n["type"] in ("char", "block") and not r.startswith("dev/"):
            out.append(("fs_misplaced_node", None, None, _ts(n["mtime_ns"]), None,
                        f"{n['type']} device node {P(n['rel'])} outside /dev", None))
        if n["type"] == "symlink" and (n["target"] or "").rstrip("/") in ("/dev/null", "dev/null") and \
                re.search(r"history$|\.log$|(^|/)(wtmp|btmp|lastlog|utmp|auth\.log|syslog|messages|secure)$", r):
            out.append(("fs_history_to_null", None, None, _ts(n["mtime_ns"]), None,
                        f"{P(n['rel'])} is a link to /dev/null: everything written to it is thrown away "
                        f"(link created {_ts(n['mtime_ns'])} UTC)", None))
            tl.append((n["mtime_ns"], "L", P(n["rel"]), "linked to /dev/null", None))
    for f in sysfiles:
        r = R(f["rel"])
        own = is_owned(f["rel"])
        if r.startswith("dev/") and not r.startswith(("dev/shm/", "dev/.udev", "dev/mqueue/")):
            out.append(("fs_misplaced_node", f["id"], None, _ts(f["mtime_ns"]), None,
                        f"regular file {P(f['rel'])} inside /dev, where only device nodes belong ({f['size']} bytes)", None))
        if not own and re.match(r"(usr/)?lib/modules/.+\.ko(\.xz|\.gz|\.zst)?$", r):
            out.append(("fs_unowned_module", f["id"], None, _ts(f["mtime_ns"]), None,
                        f"kernel module {P(f['rel'])} was not installed by any package (modified {_ts(f['mtime_ns'])} UTC)", None))
        temp_or_hidden = bool(SUSPICIOUS_LOC.search(r)) or r.startswith("run/")
        if not own and "ELF" in (f["magic"] or "") and temp_or_hidden:
            out.append(("fs_exec_in_temp", f["id"], None, _ts(f["mtime_ns"]), None,
                        f"program {P(f['rel'])} ({f['size']} bytes, owner {who(f['uid'])}) stored in a temporary, web or "
                        f"hidden folder; modified {_ts(f['mtime_ns'])} UTC", None))

    # ---------------------------------------------------------------- 8. optional Sleuth Kit bodyfile
    body = _bodyfile(root, files)
    body_info = None
    if body:
        brel, entries = body
        deleted = 0
        for e in entries:
            r = e["name"].lstrip("/")
            if NOISE.search(r):
                continue
            if e["deleted"]:
                deleted += 1
                if INTEREST.match(r) and deleted <= 600:
                    t = max(e["m"], e["c"]) * 10**9
                    out.append(("fs_deleted_entry", None, None, _ts(t) if t else None, None,
                                f"deleted: {e['name']} ({e['size']} bytes, inode {e['inode']}, modified "
                                f"{_ts(e['m'] * 10**9)}, changed {_ts(e['c'] * 10**9)} UTC)", None))
                    tl.append((t, "X", e["name"], f"deleted (inode {e['inode']}, {e['size']} bytes) per bodyfile", None))
            elif e["b"] and e["m"] and e["b"] - e["m"] > 60 and INTEREST.match(r):
                f = by_rel.get(pre + r)
                out.append(("fs_born_after_modified", f["id"] if f else None, None, _ts(e["b"] * 10**9), None,
                            f"{e['name']} was created {_ts(e['b'] * 10**9)} but claims to be modified "
                            f"{_ts(e['m'] * 10**9)} UTC, {_dur(e['b'] - e['m'])} before it existed", None))
                tl.append((e["b"] * 10**9, "B", e["name"], f"created; modified time claims {_ts(e['m'] * 10**9)}", None))
        body_info = {"file": brel, "entries": len(entries), "deleted": deleted}

    # ---------------------------------------------------------------- 9. timeline of everything not pristine
    for f in sysfiles:
        rel = f["rel"]
        r = R(rel)
        if NOISE.search(r) or not f["mtime_ns"]:
            continue
        rr = _resolve(rel, al)
        e = expected.get(rr)
        if rel.startswith(info_dir):
            if rel.endswith(".list"):
                tl.append((f["mtime_ns"], "P", rel[len(info_dir):-5], "package installed or upgraded (dpkg record written)", None))
            continue
        if e and f["md5"] == e[0]:
            continue                    # byte-identical to its package: not activity on this system
        info = (("CLAIMED TIME, set back; " if rel in backdated else "")
                + f"{status_of(f)}; owner {who(f['uid'])}; {f['size']} bytes; mode {oct((f['mode'] or 0) & 0o7777)}")
        tl.append((f["mtime_ns"], "M", P(rel), info, None))
        if ctime_ok and f["ctime_ns"] and abs(f["ctime_ns"] - f["mtime_ns"]) > 60 * 10**9:
            tl.append((f["ctime_ns"], "C", P(rel), "inode changed (permissions, owner, rename or time reset)", None))
    for n in nodes:
        if n["rel"].startswith(pre) and n["type"] == "symlink" and not is_owned(n["rel"]) and INTEREST.match(R(n["rel"])):
            tl.append((n["mtime_ns"], "L", P(n["rel"]), f"link -> {n['target']}", None))

    for path, (ts, fid, ln, cmd, _ref) in touched.items():
        tl.append((_ns(ts), "T", path, f"timestamp set by: {cmd[:150]}", None))

    tl_fid, days = _write_timeline(con, root, tl)

    counts = Counter(x[0] for x in out)
    summary = {"available": True, "prefix": pre, "os": os_name, "os_install": _ts(os_install),
               "copy_time": None if ctime_ok else _ts(copy_mid), "ctime_reliable": ctime_ok, "atime_reliable": atime_ok,
               "subsecond_share": round(ns_share, 3), "coverage": round(coverage, 3), "complete": complete,
               "files": len(sysfiles), "owned": len(owned), "packages": len(installed),
               "pristine": sum(1 for f in sysfiles if f["status"] == "pristine"),
               "users": len(users), "bodyfile": body_info, "timeline_file_id": tl_fid, "timeline_days": days,
               "counts": dict(counts), "notes": notes}
    con.execute("DELETE FROM facts WHERE scope='case' AND kind='fsweep'")
    con.execute("INSERT INTO facts(kind, scope, ts, subject, data) VALUES('fsweep','case',NULL,'fsweep',?)",
                (json.dumps(summary),))
    return out


def _dpkg_installed(txt):
    out, pkg, ver = {}, None, None
    for line in txt.splitlines():
        if line.startswith("Package: "):
            pkg, ver = line[9:].strip(), None
        elif line.startswith("Version: "):
            ver = line[9:].strip()
        elif line.startswith("Status: ") and pkg and line.rstrip().endswith(" installed"):
            out[pkg] = ver or "?"
    return out


def _bodyfile(root, files):
    """Sleuth Kit bodyfile (fls -r -m / image > bodyfile.txt) dropped into the evidence folder."""
    for f in files:
        if re.search(r"(?i)(^|/)(bodyfile[^/]*|[^/]+\.body)$", f["rel"]) and (f["size"] or 0) > 0:
            entries = []
            try:
                with open(os.path.join(root, f["rel"]), encoding="utf-8", errors="replace") as fh:
                    for i, line in enumerate(fh):
                        if i > 3_000_000:
                            break
                        p = line.rstrip("\n").split("|")
                        if len(p) < 11:
                            continue
                        try:
                            name = "|".join(p[1:len(p) - 9])
                            vals = [int(x or 0) for x in p[-7:]]   # uid gid size atime mtime ctime crtime
                        except ValueError:
                            continue
                        deleted = "(deleted" in name
                        name = re.sub(r"\s*\(deleted(-realloc)?\)\s*$", "", name.split(" -> ")[0])
                        entries.append({"name": name, "inode": p[len(p) - 9], "deleted": deleted, "size": vals[2],
                                        "a": vals[3], "m": vals[4], "c": vals[5], "b": vals[6]})
            except OSError:
                continue
            if entries:
                return f["rel"], entries
    return None


def _write_timeline(con, root, tl):
    """Write the generated timeline as a searchable file. Returns (file id, per-day counts)."""
    rows, seen = [], set()
    for ns, flag, path, info, _k in tl:
        if (ns, path, info.split(" ")[0]) not in seen and not (flag == "L" and (ns, path, "link") in seen):
            seen.add((ns, path, info.split(" ")[0]))
            seen.add((ns, path, "link") if flag == "L" else (ns, path, flag))
            rows.append(((ns or 0), flag, path, info))
    rows.sort()
    dated = [r for r in rows if r[0]]
    undated = [r for r in rows if not r[0]]
    lines = []
    for ns, flag, path, info in (dated + undated)[:300_000]:
        ts = _ts(ns) if ns else None
        lines.append((ts, f"{ts or '(time unknown)      '}  {flag}  {path}  [{info}]"))
    if not lines:
        return None, {}
    first = next((t for t, _x in lines if t), None)
    last = next((t for t, _x in reversed(lines) if t), None)
    size = sum(len(x) + 1 for _t, x in lines)
    cur = con.execute(
        "INSERT INTO files(path, rel, name, ext, size, status, kind, line_count, first_ts, last_ts, ts_count, note, "
        "encoding, indexed_at) VALUES(?,?,?,?,?,'ok','text',?,?,?,?,?, 'utf-8', datetime('now'))",
        (os.path.join(root, "[crumbs]", "filesystem-timeline.txt"), TIMELINE_REL, "filesystem-timeline.txt", "txt",
         size, len(lines), first, last, sum(1 for t, _x in lines if t),
         "Generated by Crumbs from file system metadata (UTC). Flags: M modified, C inode changed, D folder lost an "
         "entry, X deleted/missing, R referenced but gone, T timestamp set by a command, L link, B born, P package installed"))
    fid = cur.lastrowid
    con.executemany("INSERT INTO lines(file_id, line_no, ts, text) VALUES(?,?,?,?)",
                    [(fid, i + 1, t, x) for i, (t, x) in enumerate(lines)])
    try:
        con.execute("INSERT INTO lines_fts(rowid, text) SELECT id, text FROM lines WHERE file_id=?", (fid,))
    except Exception:
        pass
    days = Counter(t[:10] for t, x in lines if t and "  P  " not in x[:28])
    return fid, dict(sorted(days.items()))
