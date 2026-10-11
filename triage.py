"""
Triage: the investigator's verdicts on findings, and what Crumbs learns from them.

A verdict is 'valid', 'fp' (false positive) or 'unsure', with a scope that decides how far it reaches:

    this       just this finding (survives re-indexing: matched by rule + file + line, or by its text)
    pattern    every finding of this rule whose text is the same apart from numbers, IPs, hashes, times
    rule_file  this rule in this file
    rule       this rule everywhere
    value      every finding that mentions a value (fp: a benign value such as your admin's IP;
               valid: a confirmed indicator of compromise)

Verdicts live outside the indexed data, so a rebuild keeps them; after every index run and every
verdict the per-finding table `finding_verdicts` is recomputed.

What the analysis learns:
  * dismissed findings drop out of timelines, stories and the Host view;
  * each rule gets a precision estimate from your verdicts, used to rank the queue;
  * values on confirmed lines (IPs, domains, URLs, e-mails, hashes, suspicious paths, accounts)
    become confirmed IOCs; findings that mention them, or happen within 30 minutes of confirmed
    activity, rise in the queue; lines that mention them but were never flagged become leads.
"""
import ipaddress
import json
import re
import time

import analyzers as az

PERSISTENT_SQL = """
CREATE TABLE IF NOT EXISTS verdicts(
    id INTEGER PRIMARY KEY, verdict TEXT, scope TEXT, rule TEXT, rel TEXT, line_no INTEGER,
    pattern TEXT, value TEXT, note TEXT, snippet TEXT, created TEXT);
CREATE TABLE IF NOT EXISTS iocs(
    id INTEGER PRIMARY KEY, value TEXT UNIQUE COLLATE NOCASE, type TEXT, note TEXT, created TEXT);
"""
DATA_SQL = """
CREATE TABLE IF NOT EXISTS finding_verdicts(
    finding_id INTEGER PRIMARY KEY, verdict TEXT, verdict_id INTEGER, how TEXT);
CREATE INDEX IF NOT EXISTS idx_fv_verdict ON finding_verdicts(verdict);
"""
SCOPES = ("this", "pattern", "rule_file", "rule", "value")
SCOPE_RANK = {"this": 5, "pattern": 4, "rule_file": 3, "value": 2, "rule": 1}
FP_EXCLUDE = "NOT EXISTS (SELECT 1 FROM finding_verdicts fvx WHERE fvx.finding_id = fi.id AND fvx.verdict = 'fp')"

_N_TS = re.compile(r"\d{4}-\d\d-\d\d[ T]\d\d:\d\d(?::\d\d(?:\.\d+)?)?|[A-Z][a-z]{2}\s+\d{1,2} \d\d:\d\d:\d\d")
_N_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}\b", re.I)
_N_HEX = re.compile(r"\b[0-9a-f]{8,}\b", re.I)
_N_NUM = re.compile(r"\d+")


def norm(snippet):
    """Snippet with the variable parts replaced, so 'the same finding elsewhere' can be recognised."""
    s = (snippet or "").lstrip("…").lower()
    s = _N_TS.sub("<t>", s)
    s = _N_IP.sub("<ip>", s)
    s = _N_HEX.sub("<h>", s)
    s = _N_NUM.sub("#", s)
    return re.sub(r"\s+", " ", s).strip()[:300]


def ensure(con):
    con.executescript(PERSISTENT_SQL + DATA_SQL)


# ------------------------------------------------------------ applying ---
def apply(con):
    """Recompute finding_verdicts from verdicts. Returns {verdict_id: findings covered}."""
    ensure(con)
    con.execute("DELETE FROM finding_verdicts")
    vs = [dict(r) for r in con.execute("SELECT * FROM verdicts ORDER BY id")]
    if not vs:
        return {}
    this_line, this_norm, pattern, rule_file, rule_all, values = {}, {}, {}, {}, {}, []
    for v in vs:
        sc = v["scope"]
        if sc == "this":
            this_line[(v["rule"], v["rel"], v["line_no"])] = v
            this_norm[(v["rule"], v["rel"], v["pattern"])] = v
        elif sc == "pattern":
            pattern[(v["rule"], v["pattern"])] = v
        elif sc == "rule_file":
            rule_file[(v["rule"], v["rel"])] = v
        elif sc == "rule":
            rule_all[v["rule"]] = v
        elif sc == "value" and v["value"]:
            values.append((v["value"].lower(), v))
    pattern_rules = {r for r, _p in pattern} | {r for r, _rel, _p in this_norm}
    out, covered = [], {}
    for f in con.execute("SELECT fi.id, fi.rule, fi.line_no, fi.snippet, f.rel FROM findings fi "
                         "LEFT JOIN files f ON f.id = fi.file_id"):
        rule, rel = f["rule"], f["rel"]
        hit, how = this_line.get((rule, rel, f["line_no"])), "this"
        if not hit and rule in pattern_rules:
            nz = norm(f["snippet"])
            hit = this_norm.get((rule, rel, nz))
            if not hit:
                hit, how = pattern.get((rule, nz)), "pattern"
        if not hit:
            hit, how = rule_file.get((rule, rel)), "rule_file"
        if not hit and values:
            low = (f["snippet"] or "").lower()
            for val, v in values:
                if v["verdict"] == "fp" and val in low:
                    hit, how = v, "value"
                    break
        if not hit:
            hit, how = rule_all.get(rule), "rule"
        if hit:
            out.append((f["id"], hit["verdict"], hit["id"], how))
            covered[hit["id"]] = covered.get(hit["id"], 0) + 1
    con.executemany("INSERT INTO finding_verdicts(finding_id, verdict, verdict_id, how) VALUES(?,?,?,?)", out)
    _CACHE.clear()
    return covered


def add(con, finding_id, verdict, scope, value=None, note=None):
    if verdict not in ("valid", "fp", "unsure") or scope not in SCOPES:
        raise ValueError("bad verdict or scope")
    f = con.execute("SELECT fi.rule, fi.line_no, fi.snippet, f.rel FROM findings fi LEFT JOIN files f ON f.id = fi.file_id "
                    "WHERE fi.id = ?", (finding_id,)).fetchone()
    if not f:
        raise KeyError("finding")
    if scope == "value" and not (value or "").strip():
        raise ValueError("a value is needed for this scope")
    if scope == "value" and verdict == "valid":
        add_ioc(con, value.strip(), note=note or f"confirmed from {f['rule']}")
    # a narrower verdict replaces an identical older one
    con.execute("DELETE FROM verdicts WHERE scope=? AND rule IS ? AND rel IS ? AND line_no IS ? AND value IS ?",
                (scope, f["rule"] if scope != "value" else None, f["rel"] if scope in ("this", "rule_file") else None,
                 f["line_no"] if scope == "this" else None, value.strip() if scope == "value" else None))
    cur = con.execute(
        "INSERT INTO verdicts(verdict, scope, rule, rel, line_no, pattern, value, note, snippet, created) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (verdict, scope, f["rule"] if scope != "value" else None, f["rel"] if scope in ("this", "rule_file") else None,
         f["line_no"] if scope == "this" else None, norm(f["snippet"]) if scope in ("this", "pattern") else None,
         value.strip() if scope == "value" else None, note, (f["snippet"] or "")[:400], time.strftime("%Y-%m-%d %H:%M:%S")))
    vid = cur.lastrowid
    covered = apply(con)
    return vid, covered.get(vid, 0)


def add_ioc(con, value, type_=None, note=None):
    ensure(con)
    con.execute("INSERT OR IGNORE INTO iocs(value, type, note, created) VALUES(?,?,?,?)",
                (value, type_ or guess_type(value), note, time.strftime("%Y-%m-%d %H:%M:%S")))
    _CACHE.clear()


def guess_type(v):
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", v, re.I):
        return "hash"
    if v.startswith(("http://", "https://")):
        return "url"
    if "@" in v:
        return "email"
    if v.startswith("/"):
        return "path"
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", v, re.I):
        return "domain"
    return "text"


# ------------------------------------------------------------ learning ---
_CACHE = {}
_PATH = re.compile(r"(?<![\w.:/])/(?:[\w.@+-]+/)+[\w.@+-]+")
IOC_TYPES = {"ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "hash", "unix_path"}
BORING = {"127.0.0.1", "0.0.0.0", "::1", "localhost", "/bin/bash", "/bin/sh", "/usr/bin/bash", "/dev/null", "/tmp", "/root"}


def _suspicious_path(p):
    return bool(re.search(r"/(?:tmp|var/tmp|dev/shm|run/shm)/|/\.[^/]+|/uploads?/|\.(?:php\d?|phtml|jsp|aspx?|sh|py|pl|elf|so|ko)$", p))


def confirmed_iocs(con):
    """Values on lines of confirmed findings, plus IOCs entered by hand. Benign values are removed."""
    key = ("iocs", _version(con))
    if key in _CACHE:
        return _CACHE[key]
    ensure(con)
    benign = {r[0].lower() for r in con.execute("SELECT value FROM verdicts WHERE scope='value' AND verdict='fp'")}
    out = {}
    for r in con.execute("SELECT value, type, note FROM iocs"):
        out[r[0].lower()] = {"value": r[0], "type": r[1], "source": "added by you", "note": r[2], "findings": 0}
    for f in con.execute("SELECT fi.id, fi.rule, fi.file_id, fi.line_no, fi.snippet, l.text FROM finding_verdicts v "
                         "JOIN findings fi ON fi.id = v.finding_id LEFT JOIN lines l ON l.file_id = fi.file_id "
                         "AND l.line_no = fi.line_no WHERE v.verdict = 'valid'"):
        text = f["text"] or f["snippet"] or ""
        ents = list(az.extract_entities(text[:4000]))
        ents += [("unix_path", m.group(0).rstrip(".,;:'\")"), None) for m in _PATH.finditer(text[:4000])]
        for etype, val, _meta in ents:
            if etype not in IOC_TYPES:
                continue
            low = val.lower()
            if low in BORING or low in benign or len(low) < 4:
                continue
            if etype in ("ipv4", "ipv6"):
                try:
                    a = ipaddress.ip_address(val)
                    if a.is_loopback or a.is_unspecified or a.is_multicast:
                        continue
                except ValueError:
                    continue
            if etype == "unix_path" and not _suspicious_path(val):
                continue
            x = out.setdefault(low, {"value": val, "type": etype, "source": f"confirmed finding ({f['rule']})", "findings": 0})
            x["findings"] += 1
    res = sorted(out.values(), key=lambda x: (-x["findings"], x["value"]))[:300]
    _CACHE[key] = res
    return res


def rule_precision(con):
    """Per rule: how often your explicit judgements found it right. Only verdicts aimed at the rule
    itself count (this finding, its pattern, the rule in a file, the whole rule); each verdict counts
    at most 3 times, so one broad verdict does not swamp the estimate. Value-based dismissals
    ('this IP is benign') say nothing about the rule and are ignored. Prior: 1 valid + 1 FP."""
    res = {}
    for r in con.execute("SELECT fi.rule, v.verdict, v.verdict_id, count(*) n FROM finding_verdicts v "
                         "JOIN findings fi ON fi.id = v.finding_id WHERE v.how IN ('this','pattern','rule_file','rule') "
                         "GROUP BY fi.rule, v.verdict, v.verdict_id"):
        c = res.setdefault(r["rule"], {"valid": 0, "fp": 0, "unsure": 0})
        c[r["verdict"]] += min(r["n"], 3)
    for rule, c in res.items():
        c["precision"] = round((c["valid"] + 1) / (c["valid"] + c["fp"] + 2), 2)
    return res


def preview(con, finding_id, verdict, scope, value=None):
    """What a verdict would cover, before it is saved."""
    f = con.execute("SELECT fi.rule, fi.line_no, fi.snippet, f.rel FROM findings fi LEFT JOIN files f ON f.id = fi.file_id "
                    "WHERE fi.id = ?", (finding_id,)).fetchone()
    if not f:
        raise KeyError("finding")
    rows = con.execute("SELECT fi.id, fi.rule, fi.severity, fi.snippet, fi.line_no, f.rel, v.verdict FROM findings fi "
                       "LEFT JOIN files f ON f.id = fi.file_id LEFT JOIN finding_verdicts v ON v.finding_id = fi.id "
                       + {"this": "WHERE fi.id = ?", "rule_file": "WHERE fi.rule = ? AND f.rel IS ?", "rule": "WHERE fi.rule = ?",
                          "pattern": "WHERE fi.rule = ?", "value": "WHERE lower(fi.snippet) LIKE ?"}[scope],
                       {"this": (finding_id,), "rule_file": (f["rule"], f["rel"]), "rule": (f["rule"],),
                        "pattern": (f["rule"],), "value": ("%" + (value or "").lower() + "%",)}[scope]).fetchall()
    if scope == "pattern":
        nz = norm(f["snippet"])
        rows = [r for r in rows if norm(r["snippet"]) == nz]
    sev = {}
    rules = {}
    for r in rows:
        sev[r["severity"]] = sev.get(r["severity"], 0) + 1
        rules[r["rule"]] = rules.get(r["rule"], 0) + 1
    already = sum(1 for r in rows if r["verdict"])
    other_rules = {k: v for k, v in rules.items() if k != f["rule"]}
    warn = []
    if verdict == "fp" and sev.get("high") and scope in ("value", "rule"):
        warn.append(f"dismisses {sev['high']} high-severity finding(s)")
    if other_rules and verdict == "fp":
        warn.append("also dismisses findings of other rules: " + ", ".join(
            f"{az.RULE_INFO.get(k, {}).get('description', k)} ×{v}" for k, v in sorted(other_rules.items(), key=lambda kv: -kv[1])[:4]))
    return {"count": len(rows), "severity": sev, "already_judged": already, "warnings": warn,
            "samples": [{"id": r["id"], "rule": r["rule"], "severity": r["severity"], "rel": r["rel"], "line": r["line_no"],
                         "snippet": (r["snippet"] or "")[:200]} for r in rows[:8]]}


def confirmed_times(con):
    return sorted(x for (x,) in con.execute(
        "SELECT fi.ts FROM finding_verdicts v JOIN findings fi ON fi.id = v.finding_id WHERE v.verdict='valid' AND fi.ts IS NOT NULL"))


def _version(con):
    a = con.execute("SELECT count(*), coalesce(max(id),0) FROM verdicts").fetchone()
    b = con.execute("SELECT count(*), coalesce(max(id),0) FROM iocs").fetchone()
    c = con.execute("SELECT count(*), coalesce(max(id),0) FROM findings").fetchone()
    return tuple(a) + tuple(b) + tuple(c)


SEV_W = {"high": 3.0, "medium": 2.0, "low": 1.0, "info": 0.3}


def queue(con, status="unreviewed", severity=None, category=None, rule=None, q=None, limit=100, offset=0, sort="score"):
    """Findings ordered by how much they deserve your attention now, or by time / severity.
    Returns the page plus a timeline (daily counts over the whole filtered set) so the view can
    show the shape of what is left, not just the current page."""
    ensure(con)
    where, params = [], []
    if status == "unreviewed":
        where.append("v.verdict IS NULL")
    elif status in ("valid", "fp", "unsure"):
        where.append("v.verdict = ?")
        params.append(status)
    if severity:
        sv = severity.split(",")
        where.append("fi.severity IN (%s)" % ",".join("?" * len(sv)))
        params += sv
    if category:
        cs = category.split(",")
        where.append("fi.category IN (%s)" % ",".join("?" * len(cs)))
        params += cs
    if rule:
        where.append("fi.rule = ?")
        params.append(rule)
    if q:
        where.append("(fi.snippet LIKE ? OR f.rel LIKE ?)")
        params += ["%" + q + "%"] * 2
    sql = ("SELECT fi.id, fi.rule, fi.severity, fi.category, fi.scope, fi.file_id, fi.line_no, fi.ts, fi.ts_end, fi.snippet, "
           "f.rel, v.verdict, v.how, v.verdict_id FROM findings fi LEFT JOIN files f ON f.id = fi.file_id "
           "LEFT JOIN finding_verdicts v ON v.finding_id = fi.id" + (" WHERE " + " AND ".join(where) if where else ""))
    items = [dict(r) for r in con.execute(sql, params)]
    prec = rule_precision(con)
    iocs = confirmed_iocs(con)
    ioc_vals = [(x["value"].lower(), x["value"]) for x in iocs if len(x["value"]) >= 4][:200]
    ctimes = [az.ts_to_epoch(t) for t in confirmed_times(con)]
    ctimes = sorted(t for t in ctimes if t is not None)
    import bisect
    for it in items:
        score = SEV_W.get(it["severity"], 1.0)
        why = []
        p = prec.get(it["rule"])
        if p and p["valid"] + p["fp"] >= 2:
            score *= 0.4 + 1.2 * p["precision"]
            if p["precision"] <= 0.3:
                why.append(f"rule mostly false positives so far ({p['valid']} valid / {p['fp']} FP)")
            elif p["precision"] >= 0.7:
                why.append(f"rule usually confirmed ({p['valid']} valid / {p['fp']} FP)")
        low = (it["snippet"] or "").lower()
        linked = [orig for lv, orig in ioc_vals if lv in low]
        if linked:
            score += 2.0 + 0.3 * min(len(linked), 3)
            it["linked"] = linked[:4]
            why.append("mentions confirmed " + ", ".join(linked[:3]))
        e = az.ts_to_epoch(it["ts"]) if it["ts"] else None
        if e is not None and ctimes:
            i = bisect.bisect_left(ctimes, e)
            near = min(abs(ctimes[j] - e) for j in (i - 1, i) if 0 <= j < len(ctimes))
            if near <= 1800:
                score += 1.5 * (1 - near / 1800)
                why.append(f"within {int(near // 60)} min of confirmed activity")
        it["score"] = round(score, 2)
        it["why"] = why
        it["description"] = az.RULE_INFO.get(it["rule"], {}).get("description", it["rule"])
        # corroboration: piggy-back on the corroboration table if available
        try:
            import corroboration
            it["corr_score"], corr_kinds = corroboration.finding_corroboration(con, it["id"])
            it["corr_kinds"] = corroboration.kinds_readable(corr_kinds)
        except Exception:
            it["corr_score"] = 0; it["corr_kinds"] = []
    SEV_ORD = {"high": 0, "medium": 1, "low": 2, "info": 3}
    sorters = {
        "score": lambda x: (-x["score"], x["ts"] or "9", x["rel"] or "", x["line_no"] or 0),
        "oldest": lambda x: (x["ts"] or "9999", x["rel"] or "", x["line_no"] or 0),
        "newest": lambda x: (x["ts"] or "", x["rel"] or "", x["line_no"] or 0),
        "severity": lambda x: (SEV_ORD.get(x["severity"], 9), -x["score"], x["ts"] or "9"),
    }
    items.sort(key=sorters.get(sort, sorters["score"]), reverse=(sort == "newest"))
    # timeline of the whole filtered set (daily), with how many are still unreviewed
    tl = {}
    undated = [0, 0]
    for x in items:
        day = (x["ts"] or "")[:10]
        slot = tl.setdefault(day, [0, 0]) if day else undated
        slot[0] += 1
        if x["verdict"] is None:
            slot[1] += 1
    timeline = [{"day": d, "n": c[0], "unreviewed": c[1]} for d, c in sorted(tl.items()) if d]
    return {"total": len(items), "offset": offset, "limit": limit, "sort": sort,
            "items": items[offset:offset + limit], "timeline": timeline,
            "undated": {"n": undated[0], "unreviewed": undated[1]} if undated[0] else None,
            "categories": sorted({x["category"] for x in items if x["category"]})}


def stats(con):
    ensure(con)
    total = con.execute("SELECT count(*) FROM findings").fetchone()[0]
    by = dict(con.execute("SELECT verdict, count(*) FROM finding_verdicts GROUP BY verdict").fetchall())
    verdicts = []
    covered = dict(con.execute("SELECT verdict_id, count(*) FROM finding_verdicts GROUP BY verdict_id").fetchall())
    for r in con.execute("SELECT * FROM verdicts ORDER BY id DESC"):
        d = dict(r)
        d["covers"] = covered.get(d["id"], 0)
        d["description"] = az.RULE_INFO.get(d["rule"], {}).get("description", d["rule"]) if d["rule"] else None
        verdicts.append(d)
    prec = rule_precision(con)
    rules = []
    for rule, c in sorted(prec.items(), key=lambda kv: kv[1]["precision"]):
        rules.append(dict(c, rule=rule, description=az.RULE_INFO.get(rule, {}).get("description", rule)))
    return {"total": total, "valid": by.get("valid", 0), "fp": by.get("fp", 0), "unsure": by.get("unsure", 0),
            "unreviewed": total - sum(by.values()), "verdicts": verdicts, "rules": rules,
            "iocs": confirmed_iocs(con)}


def leads(con, fts=True, per_ioc=6):
    """Lines mentioning confirmed IOCs that no reviewed finding covers: new places to look."""
    out = []
    reviewed = set()
    for r in con.execute("SELECT fi.file_id, fi.line_no FROM finding_verdicts v JOIN findings fi ON fi.id = v.finding_id"):
        reviewed.add((r[0], r[1]))
    for ioc in confirmed_iocs(con)[:60]:
        val = ioc["value"]
        if len(val) < 3:
            continue
        try:
            if fts:
                rows = con.execute("SELECT l.file_id, l.line_no, l.ts, l.text, f.rel FROM lines_fts JOIN lines l ON l.id = lines_fts.rowid "
                                   "JOIN files f ON f.id = l.file_id WHERE lines_fts MATCH ? LIMIT 3000",
                                   ('"' + val.replace('"', '""') + '"',)).fetchall()
            else:
                rows = con.execute("SELECT l.file_id, l.line_no, l.ts, l.text, f.rel FROM lines l JOIN files f ON f.id = l.file_id "
                                   "WHERE l.text LIKE ? LIMIT 3000", ("%" + val + "%",)).fetchall()
        except Exception:
            continue
        new = [r for r in rows if (r[0], r[1]) not in reviewed]
        if not new:
            continue
        files = {}
        for r in new:
            files.setdefault(r[4], 0)
            files[r[4]] += 1
        flagged = con.execute("SELECT count(*) FROM findings fi LEFT JOIN finding_verdicts v ON v.finding_id = fi.id "
                              "WHERE v.verdict IS NULL AND fi.snippet LIKE ?", ("%" + val + "%",)).fetchone()[0]
        ts = sorted(r[2] for r in new if r[2])
        out.append({"value": val, "type": ioc["type"], "source": ioc["source"], "lines": len(new), "files": len(files),
                    "top_files": sorted(files.items(), key=lambda kv: -kv[1])[:5], "unreviewed_findings": flagged,
                    "first": ts[0] if ts else None, "last": ts[-1] if ts else None,
                    "samples": [{"file_id": r[0], "line": r[1], "ts": r[2], "rel": r[4], "text": (r[3] or "")[:220]}
                                for r in sorted(new, key=lambda r: r[2] or "9")[:per_ioc]]})
    out.sort(key=lambda x: (-x["unreviewed_findings"], -x["files"], -x["lines"]))
    return out
