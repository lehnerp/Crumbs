"""
Corroboration: how many *independent* log sources confirm a finding or entity.

A finding in auth.log gains corroborating weight when the same IP also appears
in the web access log, the firewall log, a pcap, and the wtmp — five different
source types that would have to be independently forged.

Source kinds are the path_kind() labels: auth_log, web_access, kern_log, pcap,
utmp, audit_log, mail_log, cron, dpkg/apt, tunnel_config, shell history, etc.
An entity in N distinct source kinds has a corroboration score of N.

Scores are cached in the DB (table: corroboration) and recomputed each run.
"""
import json

import linux

# Source kinds that are genuinely independent (not duplicates or derived logs)
INDEPENDENT_KINDS = {
    "auth_log", "kern_log", "mail_log", "audit_log", "web_access",
    "pcap", "utmp", "lastlog", "cron", "dpkg_log", "apt_history",
    "tunnel_config", "net_config", "shellrc", "bash_completion",
    "systemd_unit", "initscript", "ld_preload", "pam", "authorized_keys",
    "sshd_config", "sudoers", "other",   # 'other' = collected artefacts (ss, ps, etc.)
}
# Threshold labels
THRESHOLDS = [(6, "confirmed by 6+ sources", "high"), (4, "4–5 independent sources", "medium"),
              (2, "2–3 independent sources", "low"), (1, "single source", "")]

SCHEMA = """
CREATE TABLE IF NOT EXISTS corroboration(
    entity_id INTEGER PRIMARY KEY,
    score INTEGER,
    kinds TEXT,
    updated TEXT);
"""


def ensure(con):
    con.executescript(SCHEMA)


_FK_CACHE = {}   # db path → {file_id: kind}


def _file_kinds(con):
    """Map file_id → path_kind.  Cached per DB file."""
    import sqlite3
    db_path = con.execute("PRAGMA database_list").fetchone()[2]
    if db_path not in _FK_CACHE:
        _FK_CACHE.clear()
        _FK_CACHE[db_path] = {r[0]: (linux.path_kind(r[1]) or "other")
                              for r in con.execute("SELECT id, rel FROM files")}
    return _FK_CACHE[db_path]


def invalidate():
    """Call after a rebuild so the cache is refreshed."""
    _FK_CACHE.clear()


def build(con):
    """Compute and store corroboration scores for all entities."""
    ensure(con)
    import time
    fk = _file_kinds(con)
    rows = []
    for r in con.execute("SELECT e.id FROM entities e WHERE e.type IN ('ipv4','ipv6','domain','url','md5','sha1','sha256')"):
        fids = [x[0] for x in con.execute("SELECT file_id FROM entity_files WHERE entity_id=?", (r[0],))]
        kinds = {fk.get(fid, "other") for fid in fids} & INDEPENDENT_KINDS
        rows.append((r[0], len(kinds), json.dumps(sorted(kinds)), time.strftime("%Y-%m-%d %H:%M:%S")))
    con.executemany("INSERT OR REPLACE INTO corroboration(entity_id, score, kinds, updated) VALUES(?,?,?,?)", rows)
    con.commit()


def score_for(con, entity_id):
    ensure(con)
    r = con.execute("SELECT score, kinds FROM corroboration WHERE entity_id=?", (entity_id,)).fetchone()
    if not r:
        # compute on the fly if not cached
        fk = _file_kinds(con)
        fids = [x[0] for x in con.execute("SELECT file_id FROM entity_files WHERE entity_id=?", (entity_id,))]
        kinds = {fk.get(fid, "other") for fid in fids} & INDEPENDENT_KINDS
        return len(kinds), sorted(kinds)
    return r[0], json.loads(r[1])


def label(score):
    for threshold, lbl, sev in THRESHOLDS:
        if score >= threshold:
            return lbl, sev
    return "", ""


def finding_corroboration(con, finding_id):
    """
    Corroboration for a finding: the union of source kinds where any entity
    mentioned on the same line also appears in other files.
    """
    fk = _file_kinds(con)
    row = con.execute("SELECT fi.file_id, fi.snippet FROM findings fi WHERE fi.id=?", (finding_id,)).fetchone()
    if not row:
        return 0, []
    # entities on the same file
    ents = con.execute(
        "SELECT e.id FROM entities e JOIN entity_files ef ON ef.entity_id=e.id "
        "WHERE ef.file_id=? AND e.type IN ('ipv4','ipv6','domain','url','md5','sha1','sha256')",
        (row["file_id"],)).fetchall()
    kinds = set()
    for (eid,) in ents:
        fids = [x[0] for x in con.execute("SELECT file_id FROM entity_files WHERE entity_id=?", (eid,))]
        for fid in fids:
            kinds.add(fk.get(fid, "other"))
    kinds &= INDEPENDENT_KINDS
    return len(kinds), sorted(kinds)


def episode_corroboration(con, episode_data):
    """
    Corroboration for an episode: count distinct independent source kinds
    across all files that contributed to it.
    """
    fk = _file_kinds(con)
    kinds = set()
    for f in episode_data.get("files", []):
        k = fk.get(f.get("file_id"), "other")
        kinds.add(k)
    for s in episode_data.get("signals", []):
        k = fk.get(s.get("file_id"), "other")
        kinds.add(k)
    for r in episode_data.get("related", []):
        k = fk.get(r.get("file_id"), "other")
        kinds.add(k)
    kinds &= INDEPENDENT_KINDS
    return len(kinds), sorted(kinds)


KIND_LABEL = {
    "auth_log": "auth logs", "kern_log": "kernel/firewall log", "mail_log": "mail logs",
    "audit_log": "auditd", "web_access": "web access log", "pcap": "packet capture",
    "utmp": "login records (wtmp/btmp)", "lastlog": "lastlog", "cron": "cron job",
    "dpkg_log": "dpkg log", "apt_history": "apt history", "tunnel_config": "tunnel config",
    "net_config": "network config", "shellrc": "shell config", "bash_completion": "bash completion",
    "systemd_unit": "systemd unit", "initscript": "init script", "ld_preload": "ld.so.preload",
    "pam": "PAM config", "authorized_keys": "authorized_keys", "sshd_config": "sshd config",
    "sudoers": "sudoers", "other": "collected artefacts",
}


def kinds_readable(kinds):
    return [KIND_LABEL.get(k, k) for k in kinds]
