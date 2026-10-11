"""
Crumbs: local forensic search dashboard.

    python app.py /path/to/evidence            # index + serve on http://127.0.0.1:8765
    python app.py /path/to/evidence --db case42.db --port 9000
    python app.py                               # serve existing DB, pick folder in the UI
"""
import argparse
import json
import os
import re
import sqlite3
import time
from datetime import datetime

from flask import Flask, abort, g, jsonify, make_response, request, send_file, send_from_directory

import analyzers as az
import triage
import toolhunt
import intel
import corroboration
from indexer import Indexer, connect, get_meta, init_db, ns_ts, purge_invalid_entities, _dur

HERE = os.path.dirname(os.path.abspath(__file__))
# Front-end files may sit in ./static/ (zip layout) or next to app.py (files downloaded one by one).
ASSET_DIRS = [os.path.join(HERE, "static"), HERE, os.path.join(HERE, "static", "vendor"), os.path.join(HERE, "vendor")]
app = Flask(__name__, static_folder=None)
CFG = {"db": "crumbs.db", "query_timeout": 20.0}
INDEXER = None

SEV_RANK_SQL = "CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END"
BUCKETS = {"minute": 16, "hour": 13, "day": 10, "month": 7}


# ------------------------------------------------------------------- helpers ---
def db():
    if "db" not in g:
        g.db = connect(CFG["db"])
    return g.db


@app.teardown_appcontext
def _close(_exc):
    con = g.pop("db", None)
    if con is not None:
        con.close()


def fts_enabled():
    return get_meta(db(), "fts", "0") == "1"


def arg_int(name, default, lo=None, hi=None):
    try:
        v = int(request.args.get(name, default))
    except (TypeError, ValueError):
        v = default
    if lo is not None:
        v = max(lo, v)
    if hi is not None:
        v = min(hi, v)
    return v


def rows(cur):
    return [dict(r) for r in cur]


class Timeout(Exception):
    pass


def run_limited(sql, params, seconds=None):
    """Run a query that aborts after `seconds` so a runaway regex can't hang the UI."""
    con = db()
    deadline = time.time() + (seconds or CFG["query_timeout"])
    con.set_progress_handler(lambda: 1 if time.time() > deadline else 0, 20000)
    try:
        return con.execute(sql, params).fetchall()
    except sqlite3.OperationalError as e:
        if "interrupt" in str(e).lower():
            raise Timeout()
        raise
    finally:
        con.set_progress_handler(None, 0)


def escape_like(s):
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


QFIELDS = {"file": "file", "path": "file", "ext": "ext", "after": "after", "from": "after", "since": "after",
           "before": "before", "to": "before", "until": "before", "rule": "rule", "sev": "sev", "severity": "sev",
           "cat": "cat", "category": "cat", "has": "has", "ep": "ep", "episode": "ep"}
_QTOK = re.compile(r'(-)?(?:(\w+):)?(?:"((?:[^"]|"")*)"|(\S+))')


def parse_query(q):
    """Boolean search: words and "quoted phrases" must all appear (any order); OR between terms;
    -term excludes; field:value filters (file: ext: after: before: rule: sev: cat: has:)."""
    groups, nots, flt = [], [], {}
    join_or = False
    for m in _QTOK.finditer(q):
        neg, field, quoted, bare = m.groups()
        val = quoted.replace('""', '"') if quoted is not None else bare
        if field and field.lower() in QFIELDS:
            key = QFIELDS[field.lower()]
            flt.setdefault(key, []).append((val, bool(neg)))
            continue
        if field:  # "host:web01" style text that is not a known field: keep it literal
            val = f"{field}:{val}"
        if not quoted and val == "OR":
            join_or = True
            continue
        if not val:
            continue
        if neg:
            nots.append(val)
        elif join_or and groups:
            groups[-1].append(val)
        else:
            groups.append([val])
        join_or = False
    return {"groups": groups, "nots": nots, "filters": flt}


def _fts_quote(t):
    return '"' + t.replace('"', '""') + '"'


def query_terms(q):
    return [t for g in parse_query(q)["groups"] for t in g]


def find_spans(text, q, mode, cap=50):
    try:
        if mode == "query":
            terms = query_terms(q)
            if not terms:
                return []
            rx = re.compile("|".join(re.escape(t) for t in sorted(terms, key=len, reverse=True)), re.I)
        elif mode == "regex":
            rx = re.compile(q)
        else:
            rx = re.compile(re.escape(q), 0 if mode == "case" else re.I)
    except re.error:
        return []
    out = []
    for m in rx.finditer(text):
        if m.end() == m.start():
            continue
        out.append((m.start(), m.end()))
        if len(out) >= cap:
            break
    return out


def make_snippet(text, q, mode, width=260):
    spans = find_spans(text, q, mode) if q else []
    start = 0
    if spans and spans[0][0] > width // 3:
        start = spans[0][0] - width // 3
    end = min(len(text), start + width + (spans[0][1] - spans[0][0] if spans else 0))
    rel = [(a - start, b - start) for a, b in spans if a >= start and b <= end]
    return {"snippet": text[start:end], "spans": rel, "cut_left": start > 0, "cut_right": end < len(text)}


def _finding_exists(field, values):
    col = {"rule": "x.rule", "sev": "x.severity", "cat": "x.category"}[field]
    conds, params = [], []
    for v, _neg in values:
        conds.append(f"{col} LIKE ?")
        params.append(v.replace("*", "%"))
    return ("EXISTS (SELECT 1 FROM findings x WHERE x.file_id = l.file_id AND x.line_no = l.line_no AND ("
            + " OR ".join(conds) + "))"), params


def build_query_mode(q, args):
    """SQL for the boolean query language (see parse_query)."""
    pq = parse_query(q)
    where, params = [], []
    frm = "lines l JOIN files f ON f.id = l.file_id"
    order = "l.id"
    match = []
    for g in pq["groups"]:
        if fts_enabled() and all(len(t) >= 3 for t in g):
            match.append("(" + " OR ".join(_fts_quote(t) for t in g) + ")")
        else:
            where.append("(" + " OR ".join("l.text LIKE ? ESCAPE '\\'" for _ in g) + ")")
            params += ["%" + escape_like(t) + "%" for t in g]
    for t in pq["nots"]:
        if match and len(t) >= 3:
            match.append("NOT " + _fts_quote(t))
        else:
            where.append("l.text NOT LIKE ? ESCAPE '\\'")
            params.append("%" + escape_like(t) + "%")
    if match:
        expr = " AND ".join(m for m in match if not m.startswith("NOT "))
        expr += "".join(" " + m for m in match if m.startswith("NOT "))
        frm = "lines_fts JOIN lines l ON l.id = lines_fts.rowid JOIN files f ON f.id = l.file_id"
        where.insert(0, "lines_fts MATCH ?")
        params.insert(0, expr)
        order = "lines_fts.rowid"
    fl = pq["filters"]
    for v, neg in fl.get("file", []):
        where.append(f"f.rel {'NOT ' if neg else ''}LIKE ? ESCAPE '\\'")
        params.append("%" + escape_like(v).replace("*", "%") + "%")
    for v, neg in fl.get("ext", []):
        e = v.lower() if v.startswith(".") else "." + v.lower()
        where.append(f"f.ext {'!=' if neg else '='} ?")
        params.append(e)
    for v, _neg in fl.get("after", []):
        where.append("l.ts >= ?")
        params.append(v.replace("T", " "))
    for v, _neg in fl.get("before", []):
        where.append("l.ts <= ?")
        params.append(v.replace("T", " ") + "\uffff")
    for key in ("rule", "sev", "cat"):
        if fl.get(key):
            pos = [x for x in fl[key] if not x[1]]
            neg = [x for x in fl[key] if x[1]]
            if pos:
                sql_, p_ = _finding_exists(key, pos)
                where.append(sql_)
                params += p_
            if neg:
                sql_, p_ = _finding_exists(key, neg)
                where.append("NOT " + sql_)
                params += p_
    for v, neg in fl.get("ep", []):
        eps = {n: (a, z) for n, _t, a, z, fids in episode_windows(db())}
        conds = []
        for part in v.split(","):
            e = eps.get(int(part)) if part.isdigit() else None
            if e:
                conds.append("(l.ts BETWEEN ? AND ?)")
                params += [e[0], e[1]]
        where.append(("NOT " if neg else "") + "(" + (" OR ".join(conds) or "0") + ")")
    for v, neg in fl.get("has", []):
        cond = {"finding": "EXISTS (SELECT 1 FROM findings x WHERE x.file_id = l.file_id AND x.line_no = l.line_no)",
                "time": "l.ts IS NOT NULL", "ts": "l.ts IS NOT NULL",
                "decoded": "EXISTS (SELECT 1 FROM decoded d WHERE d.file_id = l.file_id AND d.line_no = l.line_no)"}.get(v.lower())
        if cond:
            where.append(("NOT " if neg else "") + cond)
    if not match and not pq["groups"]:
        order = "l.ts, l.id"
    return frm, where, params, order


def build_line_query(q, mode, args):
    """Return (from_sql, where_list, params, order_sql)."""
    where, params = [], []
    frm = "lines l JOIN files f ON f.id = l.file_id"
    order = "l.id"
    if q and mode == "query":
        frm, where, params, order = build_query_mode(q, args)
        q = ""
    if q:
        if fts_enabled() and mode in ("substring", "case") and len(q) >= 3:
            frm = "lines_fts JOIN lines l ON l.id = lines_fts.rowid JOIN files f ON f.id = l.file_id"
            where.append("lines_fts MATCH ?")
            params.append('"' + q.replace('"', '""') + '"')
            order = "lines_fts.rowid"
            if mode == "case":
                where.append("instr(l.text, ?) > 0")
                params.append(q)
        elif mode == "regex":
            re.compile(q)  # raises re.error for the caller
            where.append("l.text REGEXP ?")
            params.append(q)
        elif mode == "case":
            where.append("instr(l.text, ?) > 0")
            params.append(q)
        else:
            where.append("l.text LIKE ? ESCAPE '\\'")
            params.append("%" + escape_like(q) + "%")
    exts = [e.strip().lower() for e in args.get("ext", "").split(",") if e.strip()]
    if exts:
        exts = [e if e.startswith(".") or e == "(none)" else "." + e for e in exts]
        where.append("f.ext IN (%s)" % ",".join("?" * len(exts)))
        params += exts
    if args.get("path"):
        where.append("f.rel LIKE ? ESCAPE '\\'")
        params.append("%" + escape_like(args["path"]) + "%")
    if args.get("file_id"):
        where.append("l.file_id = ?")
        params.append(int(args["file_id"]))
    t_from, t_to = args.get("from", "").replace("T", " "), args.get("to", "").replace("T", " ")
    if t_from:
        where.append("l.ts >= ?")
        params.append(t_from[:16])
    if t_to:
        where.append("l.ts <= ?")
        params.append(t_to[:16] + "\uffff")
    if not q and (t_from or t_to):
        order = "l.ts, l.id"
    return frm, where, params, order


# --------------------------------------------------------------------- pages ---
ASSET_EXTS = {".html", ".js", ".css", ".svg", ".png", ".ico", ".woff", ".woff2"}


def _find_asset(rel):
    rel = rel.replace("\\", "/")
    if ".." in rel.split("/") or os.path.splitext(rel)[1].lower() not in ASSET_EXTS:
        return None
    for d in ASSET_DIRS:
        for cand in (rel, os.path.basename(rel)):
            full = os.path.normpath(os.path.join(d, cand))
            if full.startswith(os.path.normpath(d)) and os.path.isfile(full):
                return d, cand
    return None


@app.get("/")
def index_page():
    hit = _find_asset("index.html")
    if not hit:
        return (f"<h2>index.html not found</h2><p>Put <code>index.html</code>, <code>app.js</code> and "
                f"<code>style.css</code> in <code>{os.path.join(HERE, 'static')}</code> "
                f"(or next to app.py).</p>"), 500
    return send_from_directory(*hit)


@app.get("/static/<path:rel>")
def static_asset(rel):
    hit = _find_asset(rel)
    if not hit:
        abort(404)
    return send_from_directory(*hit)


# ---------------------------------------------------------------- indexing ---
@app.get("/api/index/status")
def api_index_status():
    s = INDEXER.status()
    con = db()
    s["root_indexed"] = get_meta(con, "root")
    s["last_indexed"] = get_meta(con, "last_indexed")
    return jsonify(s)


@app.post("/api/index")
def api_index_start():
    body = request.get_json(silent=True) or {}
    root = body.get("root") or get_meta(db(), "root")
    if not root:
        return jsonify(error="Choose a folder to index first."), 400
    try:
        started = INDEXER.start(root, full=bool(body.get("full")), max_mb=int(body.get("max_mb") or CFG["max_mb"]))
    except ValueError as e:
        return jsonify(error=str(e)), 400
    if not started:
        return jsonify(error="Indexing is already running."), 409
    return jsonify(ok=True)


@app.post("/api/index/cancel")
def api_index_cancel():
    INDEXER.cancel()
    return jsonify(ok=True)


# ------------------------------------------------------------------ search ---
@app.get("/api/search")
def api_search():
    q = request.args.get("q", "")
    mode = request.args.get("mode", "substring")
    limit = arg_int("limit", 100, 1, 1000)
    offset = arg_int("offset", 0, 0)
    args = request.args.to_dict()
    if not q and not (args.get("from") or args.get("to") or args.get("file_id")):
        return jsonify(results=[], total=0, files=[])
    try:
        frm, where, params, order = build_line_query(q, mode, args)
    except re.error as e:
        return jsonify(error=f"Invalid regular expression: {e}"), 400
    wsql = (" WHERE " + " AND ".join(where)) if where else ""
    sql = (f"SELECT l.id, l.file_id, l.line_no, l.ts, l.text, f.rel FROM {frm}{wsql} "
           f"ORDER BY {order} LIMIT ? OFFSET ?")
    t0 = time.time()
    try:
        res = run_limited(sql, params + [limit, offset])
    except Timeout:
        return jsonify(error="Search took too long and was stopped. Narrow it with filters or a longer term."), 408
    out = []
    for r in res:
        item = {"id": r["id"], "file_id": r["file_id"], "line": r["line_no"], "ts": r["ts"], "rel": r["rel"]}
        item.update(make_snippet(r["text"] or "", q, mode))
        out.append(item)

    facets, total, capped = [], None, False
    if offset == 0 and request.args.get("facets", "1") == "1":
        cap = 20000
        fsql = (f"SELECT x.fid, count(*) c FROM (SELECT l.file_id fid FROM {frm}{wsql} LIMIT {cap}) x "
                f"GROUP BY x.fid ORDER BY c DESC")
        try:
            fac = run_limited(fsql, params, seconds=CFG["query_timeout"] / 2)
            total = sum(r["c"] for r in fac)
            capped = total >= cap
            names = {}
            ids = [r["fid"] for r in fac[:500]]
            if ids:
                for fr in db().execute("SELECT id, rel FROM files WHERE id IN (%s)" % ",".join("?" * len(ids)), ids):
                    names[fr["id"]] = fr["rel"]
            facets = [{"file_id": r["fid"], "rel": names.get(r["fid"], "?"), "count": r["c"]} for r in fac[:500]]
        except Timeout:
            total, capped = None, True
    decoded = _search_decoded(q, mode, args) if offset == 0 and q and mode in ("substring", "case", "query") else []
    return jsonify(results=out, total=total, capped=capped, files=facets, decoded=decoded,
                   took_ms=int((time.time() - t0) * 1000), engine="fts" if "lines_fts" in frm else "scan")


def _search_decoded(q, mode, args):
    """Matches inside decoded content (base64, hex, auditd arguments...) that the raw lines hide."""
    con = db()
    where, params = [], []
    if mode == "query":
        pq = parse_query(q)
        terms = [g for g in pq["groups"]]
        if not terms:
            return []
        for g in terms:
            where.append("(" + " OR ".join("d.text LIKE ? ESCAPE '\\'" for _ in g) + ")")
            params += ["%" + escape_like(t) + "%" for t in g]
        for t in pq["nots"]:
            where.append("d.text NOT LIKE ? ESCAPE '\\'")
            params.append("%" + escape_like(t) + "%")
    elif mode == "case":
        where.append("instr(d.text, ?) > 0")
        params.append(q)
    else:
        where.append("d.text LIKE ? ESCAPE '\\'")
        params.append("%" + escape_like(q) + "%")
    frm = "decoded d"
    first = mode != "query" and len(q) >= 3
    if fts_enabled() and (first or (mode == "query" and all(len(t) >= 3 for g in parse_query(q)["groups"] for t in g))):
        expr = _fts_quote(q) if mode != "query" else " AND ".join(
            "(" + " OR ".join(_fts_quote(t) for t in g) + ")" for g in parse_query(q)["groups"])
        frm = "decoded_fts JOIN decoded d ON d.id = decoded_fts.rowid"
        where.insert(0, "decoded_fts MATCH ?")
        params.insert(0, expr)
    if args.get("path"):
        where.append("f.rel LIKE ? ESCAPE '\\'")
        params.append("%" + escape_like(args["path"]) + "%")
    sql = (f"SELECT d.file_id, d.line_no, d.method, d.text, f.rel, "
           f"(SELECT ts FROM lines l WHERE l.file_id = d.file_id AND l.line_no = d.line_no) ts "
           f"FROM {frm} JOIN files f ON f.id = d.file_id WHERE {' AND '.join(where)} LIMIT 100")
    try:
        res = run_limited(sql, params, seconds=CFG["query_timeout"] / 2)
    except Timeout:
        return []
    out = []
    for r in res:
        item = {"file_id": r["file_id"], "line": r["line_no"], "method": r["method"], "rel": r["rel"], "ts": r["ts"]}
        item.update(make_snippet(r["text"] or "", q, mode))
        out.append(item)
    return out


@app.post("/api/sweep")
def api_sweep():
    """IOC sweep: how often, where and when each indicator appears (raw lines and decoded content)."""
    body = request.get_json(silent=True) or {}
    terms = []
    for t in body.get("terms", []):
        t = str(t).strip()
        if t and t not in terms:
            terms.append(t[:300])
    terms = terms[:500]
    out = []
    for t in terms:
        row = {"term": t, "lines": 0, "files": 0, "decoded": 0, "first": None, "last": None, "entity": None}
        try:
            if fts_enabled() and len(t) >= 3:
                r = run_limited("SELECT count(*) n, count(DISTINCT l.file_id) f, min(l.ts) a, max(l.ts) b FROM "
                                "(SELECT rowid FROM lines_fts WHERE lines_fts MATCH ? LIMIT 20000) x "
                                "JOIN lines l ON l.id = x.rowid", [_fts_quote(t)], seconds=5)[0]
                d = run_limited("SELECT count(*) n FROM (SELECT rowid FROM decoded_fts WHERE decoded_fts MATCH ? LIMIT 5000)",
                                [_fts_quote(t)], seconds=5)[0]
            else:
                like = "%" + escape_like(t) + "%"
                r = run_limited("SELECT count(*) n, count(DISTINCT file_id) f, min(ts) a, max(ts) b FROM "
                                "(SELECT file_id, ts FROM lines WHERE text LIKE ? ESCAPE '\\' LIMIT 20000)", [like], seconds=5)[0]
                d = run_limited("SELECT count(*) n FROM decoded WHERE text LIKE ? ESCAPE '\\'", [like], seconds=5)[0]
            row.update(lines=r["n"], files=r["f"], first=r["a"], last=r["b"], decoded=d["n"])
        except Timeout:
            row["error"] = "timed out"
        e = db().execute("SELECT type FROM entities WHERE value = ? COLLATE NOCASE LIMIT 1", (t,)).fetchone()
        row["entity"] = e[0] if e else None
        out.append(row)
    return jsonify(results=out)


# ------------------------------------------------------------------- files ---
@app.get("/api/files")
def api_files():
    con = db()
    files = rows(con.execute("SELECT id, rel, name, ext, size, line_count, status, note FROM files ORDER BY rel"))
    sev = {}
    for r in con.execute(f"SELECT file_id, count(*) n, min({SEV_RANK_SQL}) best FROM findings GROUP BY file_id"):
        sev[r["file_id"]] = (r["n"], ["high", "medium", "low", "info"][r["best"]])
    for f in files:
        n, s = sev.get(f["id"], (0, None))
        f["findings"], f["severity"] = n, s
    return jsonify(files=files)


@app.get("/api/file/<int:fid>")
def api_file(fid):
    con = db()
    f = con.execute("SELECT * FROM files WHERE id=?", (fid,)).fetchone()
    if not f:
        abort(404)
    ents = rows(con.execute(
        "SELECT e.id, e.type, e.value, e.meta, ef.hits, ef.first_line, "
        "(SELECT count(*) FROM entity_files x WHERE x.entity_id = e.id) files "
        "FROM entity_files ef JOIN entities e ON e.id = ef.entity_id WHERE ef.file_id=? "
        "ORDER BY files DESC, ef.hits DESC LIMIT 300", (fid,)))
    finds = rows(con.execute(
        f"SELECT id, rule, severity, category, scope, line_no, ts, ts_end, snippet, "
        f"(SELECT verdict FROM finding_verdicts v WHERE v.finding_id = findings.id) verdict FROM findings WHERE file_id=? "
        f"ORDER BY scope != 'line' DESC, {SEV_RANK_SQL}, line_no LIMIT 600", (fid,)))
    for x in finds:
        x["description"] = az.RULE_INFO.get(x["rule"], {}).get("description", x["rule"])
    fd = dict(f)
    fd["integrity"] = json.loads(fd["integrity"]) if fd.get("integrity") else {}
    for k in ("mtime_ns", "ctime_ns", "atime_ns", "birth_ns"):
        fd[k.replace("_ns", "_ts")] = ns_ts(fd.get(k))
    fd["ctime_kind"] = get_meta(con, "ctime_kind", "inode change")
    return jsonify(file=fd, entities=ents, findings=finds)


@app.get("/api/file/<int:fid>/lines")
def api_file_lines(fid):
    start = arg_int("start", 1, 1)
    count = arg_int("count", 400, 1, 2000)
    con = db()
    lines = []
    for r in con.execute("SELECT line_no, ts, text FROM lines WHERE file_id=? AND line_no >= ? "
                         "ORDER BY line_no LIMIT ?", (fid, start, count)):
        t = r["text"] or ""
        lines.append({"n": r["line_no"], "ts": r["ts"],
                      "text": t if len(t) <= 20000 else t[:20000] + f"  … [{len(t) - 20000:,} more chars]"})
    _time_flags(con, fid, lines)
    for n_, title, a, z, fids in episode_windows(con):
        for l in lines:
            if l["ts"] and a <= l["ts"] <= z and not l.get("ep"):
                l["ep"] = n_
                l["ep_title"] = title
    marks = {}
    if lines:
        for r in con.execute("SELECT fi.line_no, fi.rule, fi.severity, v.verdict FROM findings fi LEFT JOIN finding_verdicts v "
                             "ON v.finding_id = fi.id WHERE fi.file_id=? AND fi.line_no BETWEEN ? AND ?",
                             (fid, lines[0]["n"], lines[-1]["n"])):
            marks.setdefault(r["line_no"], []).append({"rule": r["rule"], "severity": r["severity"], "verdict": r["verdict"]})
    return jsonify(lines=lines, marks=marks)


def _order_context(con, fid, start):
    """Latest time written before line `start` (the running 'frontier') and the gap threshold."""
    f = con.execute("SELECT integrity, kind FROM files WHERE id=?", (fid,)).fetchone()
    integ = json.loads(f["integrity"]) if f and f["integrity"] else {}
    cad = integ.get("cadence_seconds")
    thr = max(1800, 25 * cad) if cad else None
    ordered = bool(cad) and not integ.get("interleaved") and (f["kind"] in ("text", "evtx"))
    row = con.execute("SELECT max(ts) FROM lines WHERE file_id=? AND line_no < ? AND ts IS NOT NULL",
                      (fid, start)).fetchone()
    return row[0], thr, ordered


def _time_flags(con, fid, lines):
    """Per line: 'back' (written earlier than lines above it), 'gap' (long silence before it)
    and 'times' (claimed, original and decoded times mentioned in the text)."""
    if not lines:
        return
    frontier, thr, ordered = _order_context(con, fid, lines[0]["n"])
    fe = az.ts_to_epoch(frontier) if frontier else None
    for l in lines:
        times = [x for x in az.line_times(l["text"], l["ts"], limit=6) if x["role"] in ("set", "previous", "decoded")]
        if times:
            l["times"] = times
        if not l["ts"]:
            continue
        e = az.ts_to_epoch(l["ts"])
        if e is None:
            continue
        if fe is not None and ordered:
            if e < fe - 300:
                l["back"] = {"seconds": fe - e, "latest": frontier}
            elif thr and e - fe > thr:
                l["gap"] = {"seconds": e - fe, "from": frontier, "label": _dur(e - fe)}
        if fe is None or e > fe:
            fe, frontier = e, l["ts"]
    for l in lines:
        if "back" in l:
            l["back"]["label"] = _dur(l["back"]["seconds"])


@app.get("/api/line")
def api_line():
    """Everything about one line: its time and position in the order, every time it mentions
    (claimed vs original vs decoded), decoded payloads and the rules that fired on it."""
    fid = arg_int("file_id", 0, 0)
    n = arg_int("n", 1, 1)
    con = db()
    r = con.execute("SELECT line_no, ts, text FROM lines WHERE file_id=? AND line_no=?", (fid, n)).fetchone()
    if not r:
        abort(404)
    line = {"n": n, "ts": r["ts"], "text": r["text"] or ""}
    _time_flags(con, fid, [line])
    frontier, _thr, _o = _order_context(con, fid, n)
    nxt = con.execute("SELECT ts, line_no FROM lines WHERE file_id=? AND line_no > ? AND ts IS NOT NULL "
                      "ORDER BY line_no LIMIT 1", (fid, n)).fetchone()
    prev = con.execute("SELECT ts, line_no FROM lines WHERE file_id=? AND line_no < ? AND ts IS NOT NULL "
                       "ORDER BY line_no DESC LIMIT 1", (fid, n)).fetchone()
    finds = rows(con.execute("SELECT fi.id, fi.rule, fi.severity, fi.snippet, v.verdict FROM findings fi LEFT JOIN finding_verdicts v "
                             "ON v.finding_id = fi.id WHERE fi.file_id=? AND fi.line_no=?", (fid, n)))
    for x in finds:
        x["description"] = az.RULE_INFO.get(x["rule"], {}).get("description", x["rule"])
    return jsonify(
        n=n, ts=line["ts"], text=line["text"][:100000], back=line.get("back"), gap=line.get("gap"),
        latest_before=frontier, prev={"ts": prev[0], "n": prev[1]} if prev else None,
        next={"ts": nxt[0], "n": nxt[1]} if nxt else None,
        times=az.line_times(line["text"], line["ts"], limit=20),
        decoded=az.decode_candidates(line["text"]), findings=finds,
        episodes=[{"n": e[0], "title": e[1], "start": e[2], "end": e[3], "in_file": fid in e[4]}
                  for e in episode_windows(con) if line["ts"] and e[2] <= line["ts"] <= e[3]])


@app.post("/api/decode")
def api_decode():
    text = (request.get_json(silent=True) or {}).get("text", "")[:200000]
    return jsonify(decoded=az.decode_candidates(text), times=az.line_times(text, None, limit=20))


@app.get("/api/file/<int:fid>/raw")
def api_file_raw(fid):
    f = db().execute("SELECT path, name FROM files WHERE id=?", (fid,)).fetchone()
    if not f or not os.path.isfile(f["path"]):
        abort(404)
    return send_file(f["path"], as_attachment=True, download_name=f["name"])


# ---------------------------------------------------------------- entities ---
@app.get("/api/entities")
def api_entities():
    where, params = [], []
    if request.args.get("type"):
        types = request.args["type"].split(",")
        where.append("e.type IN (%s)" % ",".join("?" * len(types)))
        params += types
    if request.args.get("q"):
        where.append("e.value LIKE ? ESCAPE '\\'")
        params.append("%" + escape_like(request.args["q"]) + "%")
    if request.args.get("meta"):
        where.append("e.meta = ?")
        params.append(request.args["meta"])
    min_files = arg_int("min_files", 1, 1)
    order = "files DESC, hits DESC" if request.args.get("sort", "files") == "files" else "hits DESC, files DESC"
    wsql = (" WHERE " + " AND ".join(where)) if where else ""
    sql = (f"SELECT e.id, e.type, e.value, e.meta, count(ef.file_id) files, sum(ef.hits) hits "
           f"FROM entities e JOIN entity_files ef ON ef.entity_id = e.id{wsql} "
           f"GROUP BY e.id HAVING files >= ? ORDER BY {order} LIMIT ? OFFSET ?")
    res = rows(db().execute(sql, params + [min_files, arg_int("limit", 200, 1, 2000), arg_int("offset", 0, 0)]))
    # attach any cached threat intel (no network calls) so public IPs, hashes and domains show inline
    con = db()
    intel_kinds = {"ipv4": "ip", "ipv6": "ip", "md5": "hash", "sha1": "hash", "sha256": "hash", "domain": "domain", "url": "url"}
    want = [x for x in res if x["type"] in intel_kinds]
    if want:
        vals = {x["value"] for x in want}
        cache = {}
        ph = ",".join("?" * len(vals))
        for r in con.execute(f"SELECT indicator, provider, ok, summary, data FROM intel_cache WHERE indicator IN ({ph})", tuple(vals)):
            cache.setdefault(r["indicator"].lower(), {})[r["provider"]] = {
                "ok": bool(r["ok"]), "summary": r["summary"], "data": json.loads(r["data"]) if r["data"] else None}
        for x in want:
            c = cache.get(x["value"].lower())
            x["intel"] = intel.verdict_hint(c) if c else None
            x["intel_providers"] = intel.providers_for(intel_kinds[x["type"]])
            sc, kinds = corroboration.score_for(con, x["id"])
            x["corr_score"] = sc
            x["corr_kinds"] = corroboration.kinds_readable(kinds)
    counts = rows(con.execute("SELECT type, count(*) n FROM entities GROUP BY type ORDER BY n DESC"))
    return jsonify(entities=res, types=counts, intel_keys=intel.get_keys(con))


@app.get("/api/entity/<int:eid>")
def api_entity(eid):
    con = db()
    e = con.execute("SELECT * FROM entities WHERE id=?", (eid,)).fetchone()
    if not e:
        abort(404)
    files = rows(con.execute(
        "SELECT f.id, f.rel, ef.hits, ef.first_line, ef.lines FROM entity_files ef "
        "JOIN files f ON f.id = ef.file_id WHERE ef.entity_id=? ORDER BY ef.hits DESC LIMIT 500", (eid,)))
    for f in files:
        f["lines"] = [int(x) for x in (f["lines"] or "").split(",") if x]
    related = rows(con.execute(
        "SELECT e2.id, e2.type, e2.value, e2.meta, count(*) shared FROM entity_files a "
        "JOIN entity_files b ON b.file_id = a.file_id AND b.entity_id != a.entity_id "
        "JOIN entities e2 ON e2.id = b.entity_id WHERE a.entity_id=? "
        "GROUP BY e2.id ORDER BY shared DESC, e2.type LIMIT 40", (eid,)))
    kinds = {"ipv4": "ip", "ipv6": "ip", "md5": "hash", "sha1": "hash", "sha256": "hash", "domain": "domain", "url": "url"}
    corr_score, corr_kinds = corroboration.score_for(con, eid)
    intel_block = None
    if e["type"] in kinds:
        intel_block = {"value": e["value"], "type": kinds[e["type"]], "providers": intel.providers_for(kinds[e["type"]]),
                       "cached": intel.all_cached(con, e["value"]), "keys": intel.get_keys(con)}
        intel_block["assessment"] = intel.verdict_hint(intel_block["cached"]) if intel_block["cached"] else None
    return jsonify(entity=dict(e), files=files, related=related, intel=intel_block,
                   corr_score=corr_score, corr_kinds=corroboration.kinds_readable(corr_kinds))


# ---------------------------------------------------------------- findings ---
@app.get("/api/findings")
def api_findings():
    where, params = [], []
    if request.args.get("severity"):
        sv = request.args["severity"].split(",")
        where.append("fi.severity IN (%s)" % ",".join("?" * len(sv)))
        params += sv
    if request.args.get("rule"):
        where.append("fi.rule = ?")
        params.append(request.args["rule"])
    if request.args.get("category"):
        cats = request.args["category"].split(",")
        where.append("fi.category IN (%s)" % ",".join("?" * len(cats)))
        params += cats
    if request.args.get("q"):
        where.append("(fi.snippet LIKE ? ESCAPE '\\' OR f.rel LIKE ? ESCAPE '\\')")
        params += ["%" + escape_like(request.args["q"]) + "%"] * 2
    if request.args.get("dismissed") != "1":
        where.append(triage.FP_EXCLUDE)
    wsql = (" WHERE " + " AND ".join(where)) if where else ""
    sql = (f"SELECT fi.id, fi.rule, fi.severity, fi.category, fi.scope, fi.line_no, fi.ts, fi.ts_end, "
           f"fi.snippet, fi.file_id, f.rel, (SELECT verdict FROM finding_verdicts v WHERE v.finding_id = fi.id) verdict "
           f"FROM findings fi LEFT JOIN files f ON f.id = fi.file_id{wsql} "
           f"ORDER BY CASE fi.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, "
           f"f.rel, fi.line_no LIMIT ? OFFSET ?")
    res = rows(db().execute(sql, params + [arg_int("limit", 200, 1, 2000), arg_int("offset", 0, 0)]))
    for x in res:
        x["description"] = az.RULE_INFO.get(x["rule"], {}).get("description", x["rule"])
    total = db().execute(f"SELECT count(*) FROM findings fi LEFT JOIN files f ON f.id = fi.file_id{wsql}", params).fetchone()[0]
    return jsonify(findings=res, total=total)


@app.get("/api/findings/summary")
def api_findings_summary():
    res = rows(db().execute(
        f"SELECT rule, severity, category, count(*) n, count(DISTINCT file_id) files FROM findings "
        f"GROUP BY rule ORDER BY {SEV_RANK_SQL}, n DESC"))
    for x in res:
        x["description"] = az.RULE_INFO.get(x["rule"], {}).get("description", x["rule"])
    return jsonify(rules=res)


# ---------------------------------------------------------------- overview ---
@app.get("/api/overview")
def api_overview():
    con = db()
    one = lambda sql, p=(): con.execute(sql, p).fetchone()[0]
    try:
        db_size = sum(os.path.getsize(CFG["db"] + s) for s in ("", "-wal") if os.path.exists(CFG["db"] + s))
    except OSError:
        db_size = 0
    return jsonify(
        root=get_meta(con, "root"), last_indexed=get_meta(con, "last_indexed"), fts=fts_enabled(),
        db_path=os.path.abspath(CFG["db"]), db_size=db_size,
        files=one("SELECT count(*) FROM files"),
        files_by_status=rows(con.execute("SELECT status, count(*) n FROM files GROUP BY status")),
        bytes=one("SELECT coalesce(sum(size),0) FROM files"),
        lines=one("SELECT coalesce(sum(line_count),0) FROM files"),
        by_ext=rows(con.execute("SELECT ext, count(*) n, sum(size) size FROM files GROUP BY ext ORDER BY n DESC LIMIT 15")),
        entity_types=rows(con.execute("SELECT type, count(*) n FROM entities GROUP BY type ORDER BY n DESC")),
        severity=rows(con.execute(f"SELECT severity, count(*) n FROM findings GROUP BY severity ORDER BY min({SEV_RANK_SQL})")),
        top_rules=api_findings_summary().get_json()["rules"][:12],
        pivots=rows(con.execute(
            "SELECT e.id, e.type, e.value, e.meta, count(*) files, sum(ef.hits) hits FROM entities e "
            "JOIN entity_files ef ON ef.entity_id = e.id WHERE e.type NOT IN ('user') "
            "GROUP BY e.id HAVING files >= 2 ORDER BY files DESC, hits DESC LIMIT 15")),
        public_ips=rows(con.execute(
            "SELECT e.id, e.type, e.value, e.meta, count(*) files, sum(ef.hits) hits FROM entities e "
            "JOIN entity_files ef ON ef.entity_id = e.id WHERE e.meta = 'public' "
            "GROUP BY e.id ORDER BY hits DESC LIMIT 12")),
        private_ips=rows(con.execute(
            "SELECT e.id, e.type, e.value, e.meta, count(*) files, sum(ef.hits) hits FROM entities e "
            "JOIN entity_files ef ON ef.entity_id = e.id WHERE e.meta = 'private' "
            "GROUP BY e.id ORDER BY hits DESC LIMIT 12")),
        top_urls=rows(con.execute(
            "SELECT e.id, e.type, e.value, e.meta, count(*) files, sum(ef.hits) hits FROM entities e "
            "JOIN entity_files ef ON ef.entity_id = e.id WHERE e.type = 'url' "
            "GROUP BY e.id ORDER BY hits DESC LIMIT 12")),
        top_domains=rows(con.execute(
            "SELECT e.id, e.type, e.value, e.meta, count(*) files, sum(ef.hits) hits FROM entities e "
            "JOIN entity_files ef ON ef.entity_id = e.id WHERE e.type = 'domain' "
            "GROUP BY e.id ORDER BY hits DESC LIMIT 12")),
        top_tools=[dict(json.loads(r[0]), total_hits=toolhunt._tool_hits(json.loads(r[0])))
                   for r in con.execute("SELECT data FROM facts WHERE kind='tool_present'")]
                  if con.execute("SELECT 1 FROM facts WHERE kind='tool_present' LIMIT 1").fetchone() else [],
        hot_files=rows(con.execute(
            f"SELECT f.id, f.rel, count(*) n, sum(fi.severity='high') high FROM findings fi "
            f"JOIN files f ON f.id = fi.file_id GROUP BY f.id ORDER BY high DESC, n DESC LIMIT 10")),
        tamper=rows(con.execute(
            "SELECT category, count(*) n, sum(severity='high') high, min(ts) first, max(coalesce(ts_end, ts)) last "
            "FROM findings WHERE category IN (%s) GROUP BY category ORDER BY high DESC, n DESC"
            % ",".join("?" * len(az.TAMPER_CATEGORIES)), sorted(az.TAMPER_CATEGORIES))),
        categories=az.CATEGORIES,
        time_range=dict(con.execute("SELECT min(ts) first, max(ts) last, count(ts) n FROM lines WHERE ts IS NOT NULL").fetchone()),
    )


# ---------------------------------------------------------------- timeline ---
@app.get("/api/timeline")
def api_timeline():
    bucket = request.args.get("bucket", "day")
    n = BUCKETS.get(bucket, 10)
    where, params = ["l.ts IS NOT NULL"], []
    if request.args.get("from"):
        where.append("l.ts >= ?")
        params.append(request.args["from"].replace("T", " "))
    if request.args.get("to"):
        where.append("l.ts <= ?")
        params.append(request.args["to"].replace("T", " ") + "\uffff")
    if request.args.get("file_id"):
        where.append("l.file_id = ?")
        params.append(int(request.args["file_id"]))
    w = " AND ".join(where)
    con = db()
    events = {r[0]: r[1] for r in con.execute(f"SELECT substr(l.ts,1,{n}) b, count(*) FROM lines l WHERE {w} GROUP BY b", params)}
    hits = {}
    fw = w.replace("l.ts", "fi.ts").replace("l.file_id", "fi.file_id")
    for r in con.execute(
            f"SELECT substr(fi.ts,1,{n}) b, count(*) c, sum(fi.severity='high') h FROM findings fi "
            f"WHERE {fw} GROUP BY b", params):
        hits[r[0]] = (r[1], r[2] or 0)
    keys = sorted(set(events) | set(hits))
    series = [{"b": k, "events": events.get(k, 0), "findings": hits.get(k, (0, 0))[0], "high": hits.get(k, (0, 0))[1]}
              for k in keys]
    return jsonify(bucket=bucket, series=series[-3000:], truncated=len(series) > 3000)


# -------------------------------------------------------------------- host ---
INTEGRITY_RULES = ("pkg_file_modified", "conffile_modified", "unowned_binary", "suid_unusual", "elf_in_tmp",
                   "weird_name", "systemd_unit_unowned", "pam_suspicious", "ld_preload", "wtmp_wiped",
                   "wtmp_backwards", "utmp_truncated", "audit_rules_changed")


@app.get("/api/host")
def api_host():
    """Structured picture of a Linux host built from the parsed artifacts."""
    con = db()
    F = {}
    for r in con.execute("SELECT fa.kind, fa.file_id, fa.line_no, fa.ts, fa.subject, fa.data, f.rel FROM facts fa "
                         "LEFT JOIN files f ON f.id = fa.file_id ORDER BY fa.ts IS NULL, fa.ts, fa.id"):
        d = json.loads(r["data"]) if r["data"] else {}
        d.update(kind=r["kind"], file_id=r["file_id"], line=r["line_no"], ts=r["ts"], subject=r["subject"], rel=r["rel"])
        F.setdefault(r["kind"], []).append(d)
    if not F:
        return jsonify(empty=True)
    F.pop("traffic_min", None)
    host = {}
    for h in F.get("host", []):
        host[h["subject"]] = h.get("value")

    # accounts
    shadow = {x["subject"]: x for x in F.get("shadow", []) if not x.get("backup")}
    groups = {}
    for g in F.get("group", []):
        if g.get("backup"):
            continue
        for m in g.get("members", []):
            groups.setdefault(m, []).append(g["subject"])
    uid_name = {}
    accounts = []
    logins = F.get("login", [])
    lastlog = {int(x["subject"]): x for x in F.get("lastlog", []) if str(x["subject"]).isdigit()}
    backup_names = {a["subject"] for a in F.get("account", []) if a.get("backup")}
    created = {c["subject"]: c for c in F.get("account_change", []) if c.get("change") == "created"}
    for a in F.get("account", []):
        if a.get("backup"):
            continue
        name, uid = a["subject"], a.get("uid")
        uid_name[uid] = uid_name.get(uid) or name
        sh = shadow.get(name, {})
        status = sh.get("status") or ("set" if a.get("pw_field") not in ("x", "*", "!", "") else None)
        interactive = not re.search(r"(nologin|/false|/sync|/halt|/shutdown)$", a.get("shell") or "")
        flags = []
        if uid == 0 and name != "root":
            flags.append(("high", "UID 0: full root"))
        if status == "empty" and interactive:
            flags.append(("high", "no password needed"))
        if uid and 0 < uid < 1000 and interactive and status == "set":
            flags.append(("high", "system account that can log in"))
        if re.match(r"^/(tmp|var/tmp|dev/shm)(/|$)|/\.", a.get("home") or ""):
            flags.append(("medium", "home in a hidden or temporary place"))
        for g in groups.get(name, []):
            if g in ("docker", "lxd", "lxc", "disk", "shadow", "root", "kmem", "libvirt"):
                flags.append(("medium", f"group {g} is root-equivalent"))
        if sh.get("algo") in ("MD5", "DES"):
            flags.append(("low", f"{sh['algo']} password hash"))
        if backup_names and name not in backup_names:
            flags.append(("medium", "not in the passwd- backup: recently added"))
        if name in created:
            flags.append(("medium", f"created {created[name]['ts'] or ''} (auth.log)"))
        ok = [l for l in logins if l["subject"] == name and l.get("result") in ("success", "session") and l["ts"]]
        ll = lastlog.get(uid) if uid_name.get(uid) == name else None  # lastlog is per UID, not per name
        accounts.append({"name": name, "uid": uid, "gid": a.get("gid"), "shell": a.get("shell"), "home": a.get("home"),
                         "gecos": a.get("gecos"), "groups": groups.get(name, []), "password": status,
                         "algo": sh.get("algo"), "pw_changed": sh.get("ts"), "interactive": interactive,
                         "logins": len(ok), "first_login": ok[0]["ts"] if ok else None,
                         "last_login": ok[-1]["ts"] if ok else (ll["ts"] if ll else None),
                         "last_from": (ok[-1].get("ip") if ok else (ll.get("host") if ll else None)),
                         "flags": flags, "file_id": a["file_id"], "line": a["line"]})
    accounts.sort(key=lambda x: (-len([f for f in x["flags"] if f[0] == "high"]), -len(x["flags"]), not x["interactive"], x["uid"] or 0))

    # keys and their use
    keys = []
    fp_uses = {}
    for l in logins:
        if l.get("fingerprint"):
            fp_uses.setdefault(l["fingerprint"], []).append(l)
    for k in F.get("ssh_key", []):
        uses = fp_uses.get(k.get("fingerprint"), [])
        keys.append({"owner": k["subject"], "type": k.get("type"), "fingerprint": k.get("fingerprint"),
                     "comment": k.get("comment"), "options": k.get("options"), "file_id": k["file_id"], "line": k["line"],
                     "rel": k["rel"], "file_changed": k["ts"], "uses": len(uses),
                     "first_use": uses[0]["ts"] if uses else None, "last_use": uses[-1]["ts"] if uses else None,
                     "ips": sorted({u.get("ip") for u in uses if u.get("ip")})})
    known = {k["fingerprint"] for k in keys}
    unknown_keys = []
    for fp, uses in fp_uses.items():
        if fp not in known:
            unknown_keys.append({"fingerprint": fp, "type": uses[0].get("key_type"), "users": sorted({u["subject"] for u in uses}),
                                 "uses": len(uses), "first_use": uses[0]["ts"], "last_use": uses[-1]["ts"],
                                 "ips": sorted({u.get("ip") for u in uses if u.get("ip")}),
                                 "file_id": uses[0]["file_id"], "line": uses[0]["line"]})

    # logins by source
    sources = _login_sources(logins)

    integrity = rows(con.execute(
        "SELECT fi.rule, fi.severity, fi.ts, fi.snippet, fi.file_id, fi.line_no, f.rel FROM findings fi "
        "LEFT JOIN files f ON f.id = fi.file_id WHERE fi.rule IN (%s) AND %s ORDER BY %s, fi.ts"
        % (",".join("?" * len(INTEGRITY_RULES)), triage.FP_EXCLUDE, SEV_RANK_SQL), INTEGRITY_RULES))
    for x in integrity:
        x["description"] = az.RULE_INFO.get(x["rule"], {}).get("description", x["rule"])
    sshd_risky = {(r["file_id"], r["line_no"]) for r in con.execute(
        "SELECT file_id, line_no FROM findings WHERE rule IN ('sshd_risky', 'sshd_quiet', 'sshd_port', 'ssh_config_weakened')")}
    sshd = [dict(x, risky=(x["file_id"], x["line"]) in sshd_risky) for x in F.get("ssh_config", [])]
    persistence = F.get("persistence", [])
    for p in persistence:
        p["level"] = "high" if p.get("reasons") else "low"
    commands = F.get("command", [])
    for c in commands:
        c["user"] = uid_name.get(int(c["subject"]), c["subject"]) if str(c["subject"]).isdigit() else c["subject"]
    return jsonify(
        empty=False, host=host, accounts=accounts, keys=keys, unknown_keys=unknown_keys, sshd=sshd,
        sources=sources[:500], logins=[l for l in logins if l.get("result") in ("success", "session")][-2000:],
        sudo=F.get("sudo", [])[-2000:], su=F.get("su", [])[-1000:], account_changes=F.get("account_change", []),
        sudo_rules=F.get("sudo_rule", []), persistence=persistence, packages=F.get("package", []),
        commands=commands[-3000:], net=F.get("net_contact", []), episodes=_episodes(con),
        dos_tools=rows(con.execute("SELECT fi.rule, fi.severity, fi.ts, fi.snippet, fi.file_id, fi.line_no line, f.rel FROM findings fi "
                                   "JOIN files f ON f.id = fi.file_id WHERE fi.category = 'dos' AND fi.scope = 'line' AND fi.rule IN "
                                   "('dos_tool', 'mail_loop', 'smtp_tooling') AND " + triage.FP_EXCLUDE + " ORDER BY fi.ts IS NULL, fi.ts LIMIT 200")),
        sniff_signals=rows(con.execute("SELECT fi.rule, fi.severity, fi.ts, fi.snippet, fi.file_id, fi.line_no line, f.rel FROM findings fi "
                                   "JOIN files f ON f.id = fi.file_id WHERE fi.category = 'sniffing' AND fi.scope IN ('line','file') AND fi.rule NOT IN "
                                   "('sniffing_episode','mitm_episode') AND " + triage.FP_EXCLUDE + " ORDER BY fi.ts IS NULL, fi.ts LIMIT 400")),
        captures=[dict(json.loads(r[0]), rel=r[1], file_id=r[2]) for r in con.execute(
            "SELECT fa.data, f.rel, fa.file_id FROM facts fa JOIN files f ON f.id=fa.file_id WHERE fa.kind='capture'")],
        initial_access=_triaged([json.loads(r[0]) for r in con.execute("SELECT data FROM facts WHERE kind='initial_access' ORDER BY ts")],
                                con, ("ip",)),
        channels=_triaged([json.loads(r[0]) for r in con.execute("SELECT data FROM facts WHERE kind='channel' ORDER BY ts")],
                          con, ("source", "target")),
        compromise_start=get_meta(con, "compromise_start"),
        tunnels=rows(con.execute(
            "SELECT fi.rule, fi.severity, fi.ts, fi.ts_end, fi.snippet, fi.file_id, fi.line_no line, f.rel FROM findings fi "
            "LEFT JOIN files f ON f.id = fi.file_id WHERE fi.rule IN ('tunnel_installed','covert_tunnel','dns_tunnel','icmp_tunnel',"
            "'suspicious_socket','ssh_forwarding_log','tunnel','reverse_shell','beaconing','http_tunnel','http_tunnel_request',"
            "'internal_control','internal_new_source','long_control') AND " + triage.FP_EXCLUDE +
            " ORDER BY fi.ts IS NULL, fi.ts LIMIT 400")),
        sniffed_creds=[dict(json.loads(r[0]), file_id=r[1], line=r[2]) for r in con.execute(
            "SELECT data, file_id, line_no FROM facts WHERE kind='sniffed_cred' LIMIT 500")], edited=F.get("file_edited", []),
        boots=F.get("boot", []), listen=F.get("sshd_listen", []), integrity=integrity)


def _episodes(con):
    out = []
    raw = [json.loads(r[0]) for r in con.execute("SELECT data FROM facts WHERE kind='episode'")]
    episodes = sorted(raw, key=lambda d: d["n"])
    for d in episodes:
        names = {x["id"]: x["rel"] for x in con.execute(
            "SELECT id, rel FROM files WHERE id IN (%s)" % (",".join(str(int(f["file_id"])) for f in d["files"]) or "0"))}
        for f in d["files"]:
            f["rel"] = names.get(f["file_id"], "?")
        # which other episodes overlap in time?
        overlaps = []
        for other in episodes:
            if other["n"] == d["n"]:
                continue
            a_start, a_end = d.get("start") or "", d.get("end") or ""
            b_start, b_end = other.get("start") or "", other.get("end") or ""
            if a_start and a_end and b_start and b_end and a_start <= b_end and b_start <= a_end:
                overlaps.append({"n": other["n"], "title": other["title"],
                                 "start": other["start"], "end": other["end"]})
        if "kind" not in d:
            d["kind"] = "flood"   # smtp/resource episodes pre-date the kind field
        # corroboration: how many independent log kinds confirm this episode
        ep_score, ep_kinds = corroboration.episode_corroboration(con, d)
        d["corr_score"] = ep_score
        d["corr_kinds"] = corroboration.kinds_readable(ep_kinds)
        out.append(d)
    return out


_EP_CACHE = {}


def episode_windows(con):
    """[(n, title, start, end, {file ids})] for tagging lines; cached per database state."""
    key = (CFG["db"], con.execute("SELECT count(*), max(id) FROM facts WHERE kind='episode'").fetchone()[:])
    if key not in _EP_CACHE:
        _EP_CACHE.clear()
        eps = []
        for r in con.execute("SELECT data FROM facts WHERE kind='episode' ORDER BY ts"):
            d = json.loads(r[0])
            eps.append((d["n"], d["title"], d["start"], d["end"], {f["file_id"] for f in d["files"]}))
        _EP_CACHE[key] = eps
    return _EP_CACHE[key]


def _triaged(items, con, fields):
    """Apply 'benign value' verdicts and mark confirmed IOCs on fact-based rows (channels, entry candidates)."""
    benign = {r[0].lower() for r in con.execute("SELECT value FROM verdicts WHERE scope='value' AND verdict='fp'")}
    iocs = {x["value"].lower() for x in triage.confirmed_iocs(con)}
    out = []
    for it in items:
        vals = {str(it.get(f) or "").lower() for f in fields}
        vals |= {v.rsplit(":", 1)[0] for v in vals if v.count(":") == 1}  # 1.2.3.4:443 -> 1.2.3.4
        if vals & benign:
            continue
        it["confirmed"] = bool(vals & iocs)
        out.append(it)
    return out


def _login_sources(logins):
    """Successful and failed logins grouped by the address they came from (deduplicated across auth.log,
    wtmp/btmp and auditd, which often record the same login)."""
    src = {}
    seen = set()
    for l in logins:
        key = (l["ts"], l["subject"], l.get("ip"), "fail" if l.get("result") in ("failed", "invalid") else l.get("result"))
        if key in seen:
            continue
        seen.add(key)
        ip = l.get("ip") or "?"
        x = src.setdefault(ip, {"ip": ip, "success": 0, "failed": 0, "users_ok": set(), "users_tried": set(),
                                "methods": set(), "first": None, "last": None, "first_success": None, "file_id": l["file_id"], "line": l["line"]})
        if l.get("result") in ("success", "session"):
            x["success"] += 1
            x["users_ok"].add(l["subject"])
            if l.get("method"):
                x["methods"].add(l["method"])
            if not x["first_success"]:
                x["first_success"], x["file_id"], x["line"] = l["ts"], l["file_id"], l["line"]
        else:
            x["failed"] += 1
            x["users_tried"].add(l["subject"])
        if l["ts"]:
            x["first"] = x["first"] or l["ts"]
            x["last"] = l["ts"]
    sources = []
    for x in src.values():
        x.update(users_ok=sorted(x["users_ok"]), users_tried=sorted(x["users_tried"]), methods=sorted(x["methods"]),
                 public=_is_public(x["ip"]))
        x["guessed"] = x["failed"] >= 10 and x["success"] > 0
        sources.append(x)
    sources.sort(key=lambda x: (not x["guessed"], -(x["success"] > 0 and x["public"]), -x["success"], -x["failed"]))
    return sources


def _is_public(ip):
    try:
        import ipaddress as _ip
        a = _ip.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved)
    except ValueError:
        return False


# ---------------------------------------------------------------- tampering ---
def _epoch(ts):
    return az.ts_to_epoch(ts) if ts else None


def _story(events, cats):
    """Plain-language summary: extent, busiest hour, first sighting per category."""
    dated = sorted((e for e in events if e["ts"] and e["severity"] in ("high", "medium")), key=lambda e: e["ts"])
    if not dated:
        return {"headline": None, "peak": None, "firsts": []}
    ep = [_epoch(e["ts"]) for e in dated]
    best, j = (0, 0, 0), 0
    for i in range(len(ep)):
        while ep[i] - ep[j] > 3600:
            j += 1
        if i - j + 1 > best[0]:
            best = (i - j + 1, j, i)
    k, a, b = best
    window = dated[a:b + 1]
    wc = {}
    for e in window:
        wc[e["category"]] = wc.get(e["category"], 0) + 1
    firsts, seen = [], set()
    for e in dated:
        if e["category"] not in seen:
            seen.add(e["category"])
            firsts.append({k2: e[k2] for k2 in ("category", "ts", "rel", "file_id", "line_no", "description", "snippet", "severity")})
    high = sum(1 for e in dated if e["severity"] == "high")
    return {
        "headline": {"count": len(dated), "high": high, "first": dated[0]["ts"], "last": dated[-1]["ts"]},
        "peak": {"from": window[0]["ts"], "to": window[-1]["ts"], "count": k,
                 "categories": sorted(({"category": c, "label": cats.get(c, c), "n": n} for c, n in wc.items()),
                                      key=lambda x: -x["n"]),
                 "files": len({e["file_id"] for e in window if e["file_id"]})},
        "firsts": firsts,
    }


@app.get("/api/tamper")
def api_tamper():
    con = db()
    which = request.args.get("set", "tamper")
    cats = sorted(az.INTRUSION_CATEGORIES if which == "intrusion" else
                  (az.TAMPER_CATEGORIES | az.INTRUSION_CATEGORIES) if which == "all" else az.TAMPER_CATEGORIES)
    ph = ",".join("?" * len(cats))
    res = rows(con.execute(
        f"SELECT fi.id, fi.rule, fi.severity, fi.category, fi.scope, fi.file_id, fi.line_no, fi.ts, fi.ts_end, "
        f"fi.snippet, fi.detail, f.rel FROM findings fi LEFT JOIN files f ON f.id = fi.file_id "
        f"WHERE fi.category IN ({ph}) AND {triage.FP_EXCLUDE} ORDER BY fi.ts IS NULL, fi.ts, {SEV_RANK_SQL} LIMIT 20000", cats))
    for x in res:
        x["description"] = az.RULE_INFO.get(x["rule"], {}).get("description", x["rule"])
        x["detail"] = json.loads(x["detail"]) if x["detail"] else None
        if x["category"] == "timestomp" and x["snippet"]:
            claims = [t for t in az.line_times(x["snippet"]) if t["role"] in ("set", "previous")]
            if claims:
                x["claims"] = claims
    summary = {}
    for x in res:
        c = summary.setdefault(x["category"], {"category": x["category"], "label": az.CATEGORIES[x["category"]],
                                                "n": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
        c["n"] += 1
        c[x["severity"]] = c.get(x["severity"], 0) + 1
    # filesystem activity: file modifications and folder changes, for the strip under the chart
    fs = [{"t": ns_ts(r["mtime_ns"]), "id": r["id"], "rel": r["rel"]}
          for r in con.execute("SELECT id, rel, mtime_ns FROM files WHERE mtime_ns IS NOT NULL")]
    return jsonify(
        summary=sorted(summary.values(), key=lambda c: (-c["high"], -c["medium"], -c["n"])),
        events=[x for x in res if x["ts"]],
        undated=[x for x in res if not x["ts"]][:1000],
        story=_story(res, az.CATEGORIES),
        fs=fs[:50000],
        notes=json.loads(get_meta(con, "fs_notes", "[]")),
        ctime_kind=get_meta(con, "ctime_kind", "inode change"),
        categories={c: az.CATEGORIES[c] for c in cats},
    )


# ------------------------------------------------------------------- graph ---
@app.get("/api/graph")
def api_graph():
    con = db()
    limit = arg_int("limit", 120, 5, 1000)
    min_files = arg_int("min_files", 2, 1)
    types = [t for t in request.args.get("types", "").split(",") if t]
    focus = request.args.get("focus")
    params = []
    tsql = ""
    if types:
        tsql = " AND e.type IN (%s)" % ",".join("?" * len(types))
        params += types

    if focus:  # neighbourhood of a single entity: its files and what else lives in them
        eid = int(focus)
        fids = [r[0] for r in con.execute("SELECT file_id FROM entity_files WHERE entity_id=? LIMIT 60", (eid,))]
        if not fids:
            return jsonify(entities=[], files=[], edges=[])
        ph = ",".join("?" * len(fids))
        ents = rows(con.execute(
            f"SELECT e.id, e.type, e.value, e.meta, count(*) files FROM entity_files ef "
            f"JOIN entities e ON e.id = ef.entity_id WHERE ef.file_id IN ({ph}){tsql} "
            f"GROUP BY e.id ORDER BY (e.id = ?) DESC, files DESC LIMIT ?", fids + params + [eid, limit]))
    else:
        ents = rows(con.execute(
            f"SELECT e.id, e.type, e.value, e.meta, count(*) files FROM entities e "
            f"JOIN entity_files ef ON ef.entity_id = e.id WHERE 1=1{tsql} "
            f"GROUP BY e.id HAVING files >= ? ORDER BY files DESC LIMIT ?", params + [min_files, limit]))
        fids = None
    if not ents:
        return jsonify(entities=[], files=[], edges=[])
    eids = [e["id"] for e in ents]
    ph = ",".join("?" * len(eids))
    esql = f"SELECT entity_id, file_id, hits FROM entity_files WHERE entity_id IN ({ph})"
    eparams = list(eids)
    if fids:
        esql += " AND file_id IN (%s)" % ",".join("?" * len(fids))
        eparams += fids
    edges = rows(con.execute(esql, eparams))
    file_ids = sorted({e["file_id"] for e in edges})
    files = []
    if file_ids:
        ph2 = ",".join("?" * len(file_ids))
        sev = {r[0]: r[1] for r in con.execute(
            f"SELECT file_id, min({SEV_RANK_SQL}) FROM findings WHERE file_id IN ({ph2}) GROUP BY file_id", file_ids)}
        for r in con.execute(f"SELECT id, rel, name FROM files WHERE id IN ({ph2})", file_ids):
            s = sev.get(r["id"])
            files.append({"id": r["id"], "rel": r["rel"], "name": r["name"],
                          "severity": ["high", "medium", "low", "info"][s] if s is not None else None})
    return jsonify(entities=ents, files=files, edges=edges)


# -------------------------------------------------------------------- pins ---
# ------------------------------------------------------------------ triage ---
@app.get("/api/triage")
def api_triage():
    a = request.args
    res = triage.queue(db(), status=a.get("status", "unreviewed"), severity=a.get("severity"), category=a.get("category"),
                       rule=a.get("rule"), q=a.get("q"), sort=a.get("sort", "score"),
                       limit=arg_int("limit", 100, 1, 5000), offset=arg_int("offset", 0, 0))
    return jsonify(res)


@app.get("/api/triage/stats")
def api_triage_stats():
    return jsonify(triage.stats(db()))


@app.get("/api/export/episodes")
def api_export_episodes():
    import export as exp
    con = db()
    eps = _episodes(con)
    ns = request.args.get("episodes")
    if ns:
        want = {int(x) for x in ns.split(",") if x.strip().isdigit()}
        eps = [e for e in eps if e.get("n") in want]
    host_data = {}
    for r in con.execute("SELECT subject, data FROM facts WHERE kind='host'"):
        try: host_data[r["subject"]] = json.loads(r["data"]).get("value")
        except Exception: pass
    case_meta = {"root": get_meta(con, "root") or "", "hostname": host_data.get("hostname", "unknown")}
    fmt = request.args.get("format", "pdf").lower()
    if fmt == "xlsx":
        data = exp.build_xlsx(eps, case_meta)
        resp=make_response(data); resp.mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        resp.headers["Content-Disposition"]="attachment; filename=crumbs-episodes.xlsx"; return resp
    data = exp.build_pdf(eps, case_meta)
    resp=make_response(data); resp.mimetype="application/pdf"
    resp.headers["Content-Disposition"]="attachment; filename=crumbs-episodes.pdf"; return resp


@app.get("/api/fsweep")
def api_fsweep():
    """Whole-filesystem sweep: collection fidelity, deletion and timestamp evidence, timeline by day."""
    import fsweep
    con = db()
    r = con.execute("SELECT data FROM facts WHERE kind='fsweep'").fetchone()
    if not r:
        return jsonify(available=False)
    d = json.loads(r[0])
    rules = list(fsweep.RULES) + ["account_removed"]
    ph = ",".join("?" * len(rules))
    items = rows(con.execute(
        f"SELECT fi.id, fi.rule, fi.severity, fi.category, fi.file_id, fi.line_no, fi.ts, fi.snippet, f.rel "
        f"FROM findings fi LEFT JOIN files f ON f.id = fi.file_id WHERE fi.rule IN ({ph}) AND {triage.FP_EXCLUDE} "
        f"ORDER BY fi.ts IS NULL, fi.ts", rules))
    for x in items:
        x["description"] = az.RULE_INFO.get(x["rule"], {}).get("description", x["rule"])
    tl = d.get("timeline_file_id")
    day_line = {}
    if tl:
        for q in con.execute("SELECT substr(ts,1,10) day, min(line_no) FROM lines WHERE file_id=? AND ts IS NOT NULL "
                             "GROUP BY day", (tl,)):
            day_line[q[0]] = q[1]
    return jsonify(available=True, summary=d, findings=items, day_line=day_line,
                   rules={k: {"severity": v[0], "category": v[1], "description": v[2]} for k, v in fsweep.RULES.items()})


@app.get("/api/loginmap")
def api_loginmap():
    """Where logins came from: each source address placed on a world map (offline database or intel cache)."""
    import geo
    con = db()
    logins = []
    for r in con.execute("SELECT fa.file_id, fa.line_no, fa.ts, fa.subject, fa.data FROM facts fa WHERE fa.kind='login' "
                         "ORDER BY fa.ts IS NULL, fa.ts, fa.id"):
        d = json.loads(r["data"]) if r["data"] else {}
        d.update(file_id=r["file_id"], line=r["line_no"], ts=r["ts"], subject=r["subject"])
        logins.append(d)
    iocs = {x["value"].lower() for x in triage.confirmed_iocs(con)}
    points, internal, unlocated = [], [], []
    for x in _login_sources(logins):
        ip = x["ip"]
        x["ioc"] = ip.lower() in iocs
        hint = intel.verdict_hint(intel.all_cached(con, ip)) if ip and ip != "?" else None
        x["intel"] = hint
        cls = geo.classify(ip) if ip and ip != "?" else "invalid"
        if cls != "public":
            if cls in ("internal", "loopback"):
                x["class"] = cls
                internal.append(x)
            continue
        loc = geo.locate(con, ip)
        if loc:
            x.update(loc)
            points.append(x)
        else:
            unlocated.append(x)
    countries = {}
    for p in points:
        c = countries.setdefault(p.get("cc") or "?", {"cc": p.get("cc"), "country": p.get("country") or "Unknown",
                                                     "ips": 0, "success": 0, "failed": 0, "lat": p["lat"], "lon": p["lon"]})
        c["ips"] += 1
        c["success"] += p["success"]
        c["failed"] += p["failed"]
    return jsonify(dots=geo.world_dots(1.5), top=geo.LAT_TOP, bottom=geo.LAT_BOTTOM, points=points, internal=internal,
                   unlocated=unlocated, countries=sorted(countries.values(), key=lambda c: (-c["success"], -c["failed"])),
                   geo=geo.status(), total=len(points) + len(internal) + len(unlocated))


@app.get("/api/baseline")
def api_baseline():
    import baseline
    return jsonify(baseline.report(db()))


@app.get("/api/report")
def api_report():
    import report
    md = report.build(db())
    if request.args.get("download"):
        from flask import Response
        return Response(md, mimetype="text/markdown",
                        headers={"Content-Disposition": "attachment; filename=crumbs-report.md"})
    return jsonify(markdown=md)


@app.get("/api/tools")
def api_tools():
    return jsonify(tools=toolhunt.all_tools(db()), categories=list(toolhunt.CATALOG.keys()))


# -------------------------------------------------------------- threat intel ---
@app.get("/api/intel/keys")
def api_intel_keys():
    return jsonify(keys=intel.get_keys(db()), providers={p: {"label": i["label"], "key_hint": i["key_hint"],
                   "kinds": sorted(i["kinds"])} for p, i in intel.PROVIDERS.items()})


@app.post("/api/intel/keys")
def api_intel_set_key():
    b = request.get_json(silent=True) or {}
    con = db()
    try:
        intel.set_key(con, b.get("provider"), b.get("key", ""))
    except ValueError as e:
        return jsonify(error=str(e)), 400
    con.commit()
    return jsonify(keys=intel.get_keys(con))


@app.get("/api/intel")
def api_intel_get():
    """Cached intel for one indicator (no network). type optional; providers chosen from it."""
    ind = request.args.get("indicator", "").strip()
    if not ind:
        return jsonify(error="indicator required"), 400
    kind = request.args.get("type") or intel_guess(ind)
    con = db()
    results = intel.all_cached(con, ind)
    return jsonify(indicator=ind, kind=kind, results=results, providers=intel.providers_for(kind),
                   assessment=intel.verdict_hint(results), keys=intel.get_keys(con))


@app.post("/api/intel")
def api_intel_fetch():
    """Fetch intel for one indicator from the chosen providers (or all that fit). Hits the network."""
    b = request.get_json(silent=True) or {}
    ind = (b.get("indicator") or "").strip()
    if not ind:
        return jsonify(error="indicator required"), 400
    kind = b.get("type") or intel_guess(ind)
    con = db()
    provs = b.get("providers") or intel.providers_for(kind)
    force = bool(b.get("force"))
    results = {p: intel.enrich(con, p, ind, kind, force=force) for p in provs}
    return jsonify(indicator=ind, kind=kind, results=results, assessment=intel.verdict_hint(results))


@app.post("/api/intel/bulk")
def api_intel_bulk():
    """Enrich many indicators (from the IOC list). Paces itself; stops cleanly if rate limited."""
    b = request.get_json(silent=True) or {}
    items = b.get("indicators") or []
    con = db()
    out, stopped = [], None
    for it in items[:200]:
        ind = (it.get("value") or "").strip()
        kind = it.get("type") or intel_guess(ind)
        if not ind:
            continue
        res = {p: intel.enrich(con, p, ind, kind, force=bool(b.get("force"))) for p in intel.providers_for(kind)}
        out.append({"indicator": ind, "kind": kind, "results": res, "assessment": intel.verdict_hint(res)})
        if any(r.get("rate_limited") for r in res.values()):
            stopped = "rate limited; enriched " + str(len(out)) + " so far"
            break
        if any(not r.get("cached") and r.get("ok") for r in res.values()):
            time.sleep(1.0)  # be gentle on free tiers
    return jsonify(results=out, stopped=stopped)


def intel_guess(v):
    import ipaddress
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", v or "", re.I):
        return "hash"
    if (v or "").startswith(("http://", "https://")):
        return "url"
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", v or "", re.I):
        return "domain"
    return "text"


@app.get("/api/triage/leads")
def api_triage_leads():
    return jsonify(leads=triage.leads(db(), fts=fts_enabled()))


@app.get("/api/finding/<int:fid>")
def api_finding(fid):
    con = db()
    f = con.execute("SELECT fi.*, f.rel, v.verdict, v.how, v.verdict_id FROM findings fi LEFT JOIN files f ON f.id = fi.file_id "
                    "LEFT JOIN finding_verdicts v ON v.finding_id = fi.id WHERE fi.id = ?", (fid,)).fetchone()
    if not f:
        abort(404)
    d = dict(f)
    d["description"] = az.RULE_INFO.get(d["rule"], {}).get("description", d["rule"])
    d["norm"] = triage.norm(d["snippet"])
    ctx = []
    if d["line_no"] and d["file_id"]:
        ctx = rows(con.execute("SELECT line_no n, ts, substr(text, 1, 600) text FROM lines WHERE file_id=? AND line_no BETWEEN ? AND ? "
                               "ORDER BY line_no", (d["file_id"], d["line_no"] - 4, d["line_no"] + 4)))
    d["context"] = ctx
    # candidate values for a "benign value" / "confirmed IOC" verdict
    text = " ".join(c["text"] for c in ctx if c["n"] == d["line_no"]) + " " + (d["snippet"] or "")
    vals = []
    for t, v, _m in az.extract_entities(text[:4000]):
        if v not in vals and t in ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "user"):
            vals.append(v)
    vals += [m.group(0) for m in triage._PATH.finditer(text[:4000]) if m.group(0) not in vals]
    d["values"] = vals[:12]
    # cached threat intel for any IP / hash / domain on this line, and the hash of the file itself
    intel_targets = []
    for v in d["values"]:
        k = intel_guess(v)
        if k in ("ip", "hash", "domain", "url"):
            intel_targets.append({"value": v, "type": k})
    if d.get("file_id"):
        fh = con.execute("SELECT sha256, md5, rel FROM files WHERE id=?", (d["file_id"],)).fetchone()
        if fh and fh["sha256"]:
            intel_targets.insert(0, {"value": fh["sha256"], "type": "hash", "note": "sha256 of " + (fh["rel"] or "this file")})
    seen_i = set()
    d["corr_score"], corr_kinds = corroboration.finding_corroboration(con, fid)
    d["corr_kinds"] = corroboration.kinds_readable(corr_kinds)
    d["intel"] = []
    for t in intel_targets:
        if t["value"] in seen_i:
            continue
        seen_i.add(t["value"])
        t["cached"] = intel.all_cached(con, t["value"])
        t["providers"] = intel.providers_for(t["type"])
        d["intel"].append(t)
    d["intel_keys"] = intel.get_keys(con)
    # tools whose breadcrumb is this file or this rule
    d["tools"] = []
    if d.get("file_id"):
        for r in con.execute("SELECT data FROM facts WHERE kind='tool_present' AND file_id=?", (d["file_id"],)):
            d["tools"].append(json.loads(r[0]))
    same = con.execute("SELECT count(*) FROM findings WHERE rule=?", (d["rule"],)).fetchone()[0]
    same_file = con.execute("SELECT count(*) FROM findings WHERE rule=? AND file_id IS ?", (d["rule"], d["file_id"])).fetchone()[0]
    nz = d["norm"]
    same_pat = sum(1 for (sn,) in con.execute("SELECT snippet FROM findings WHERE rule=?", (d["rule"],)) if triage.norm(sn) == nz)
    d["reach"] = {"this": 1, "pattern": same_pat, "rule_file": same_file, "rule": same}
    return jsonify(d)


@app.post("/api/verdicts")
def api_verdict_add():
    b = request.get_json(silent=True) or {}
    con = db()
    try:
        vid, n = triage.add(con, int(b.get("finding_id", 0)), b.get("verdict"), b.get("scope", "this"),
                            value=b.get("value"), note=b.get("note"))
    except (ValueError, KeyError) as e:
        return jsonify(error=str(e)), 400
    con.commit()
    return jsonify(id=vid, covers=n)


@app.post("/api/verdicts/preview")
def api_verdict_preview():
    b = request.get_json(silent=True) or {}
    try:
        return jsonify(triage.preview(db(), int(b.get("finding_id", 0)), b.get("verdict"), b.get("scope", "this"), b.get("value")))
    except KeyError:
        return jsonify(error="unknown finding"), 404


@app.delete("/api/verdicts/<int:vid>")
def api_verdict_del(vid):
    con = db()
    con.execute("DELETE FROM verdicts WHERE id=?", (vid,))
    triage.apply(con)
    con.commit()
    return jsonify(ok=True)


@app.post("/api/iocs")
def api_ioc_add():
    b = request.get_json(silent=True) or {}
    v = (b.get("value") or "").strip()
    if not v:
        return jsonify(error="empty"), 400
    con = db()
    triage.add_ioc(con, v, note=b.get("note"))
    con.commit()
    return jsonify(ok=True)


@app.delete("/api/iocs")
def api_ioc_del():
    con = db()
    con.execute("DELETE FROM iocs WHERE value = ? COLLATE NOCASE", (request.args.get("value", ""),))
    triage._CACHE.clear()
    con.commit()
    return jsonify(ok=True)


@app.get("/api/pins")
def api_pins():
    con = db()
    res = rows(con.execute("SELECT * FROM pins ORDER BY created"))
    ids = {r["rel"]: r["id"] for r in con.execute("SELECT id, rel FROM files")}
    for p in res:
        p["file_id"] = ids.get(p["rel"])
    return jsonify(pins=res)


@app.post("/api/pins")
def api_pin_add():
    b = request.get_json(silent=True) or {}
    con = db()
    f = con.execute("SELECT rel FROM files WHERE id=?", (b.get("file_id"),)).fetchone()
    if not f:
        return jsonify(error="Unknown file"), 400
    ln = int(b.get("line") or 0)
    t = con.execute("SELECT text FROM lines WHERE file_id=? AND line_no=?", (b["file_id"], ln)).fetchone()
    con.execute("INSERT INTO pins(rel, line_no, text, note, created) VALUES(?,?,?,?,?)",
                (f["rel"], ln, (t["text"] if t else "")[:4000], (b.get("note") or "")[:2000],
                 datetime.now().isoformat(timespec="seconds")))
    con.commit()
    return jsonify(ok=True)


@app.patch("/api/pins/<int:pid>")
def api_pin_edit(pid):
    b = request.get_json(silent=True) or {}
    db().execute("UPDATE pins SET note=? WHERE id=?", ((b.get("note") or "")[:2000], pid))
    db().commit()
    return jsonify(ok=True)


@app.delete("/api/pins/<int:pid>")
def api_pin_delete(pid):
    db().execute("DELETE FROM pins WHERE id=?", (pid,))
    db().commit()
    return jsonify(ok=True)


@app.get("/api/rules")
def api_rules():
    return jsonify(rules=az.RULE_INFO, entity_types=list(az.ENTITY_PATTERNS))


# -------------------------------------------------------------------- main ---
def main():
    global INDEXER
    ap = argparse.ArgumentParser(description="Crumbs: local forensic search dashboard")
    ap.add_argument("folder", nargs="?", help="folder to index (optional, can be set in the UI)")
    ap.add_argument("--db", default="crumbs.db", help="SQLite database file (default: crumbs.db)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--max-mb", type=int, default=200, help="skip files larger than this (default 200)")
    ap.add_argument("--full", action="store_true", help="rebuild the index from scratch")
    ap.add_argument("--no-index", action="store_true", help="just serve the existing database")
    a = ap.parse_args()

    CFG["db"] = os.path.abspath(a.db)
    CFG["max_mb"] = a.max_mb
    con = connect(CFG["db"])
    fts = init_db(con)
    dropped = purge_invalid_entities(con)
    con.close()
    if dropped:
        print(f"Removed {dropped} implausible entities (e.g. junk Windows paths) from the existing index.")
    if not fts:
        print("! Your SQLite has no FTS5 trigram tokenizer (needs 3.34+). Search will use slower full scans.")
    INDEXER = Indexer(CFG["db"])
    if a.folder and not a.no_index:
        INDEXER.start(a.folder, full=a.full, max_mb=a.max_mb)
        print(f"Indexing {os.path.abspath(a.folder)} in the background…")
    missing = [f for f in ("index.html", "app.js", "style.css") if not _find_asset(f)]
    if missing:
        print(f"! Missing front-end files: {', '.join(missing)}. Put them in {os.path.join(HERE, 'static')}")
    print(f"Database: {CFG['db']}")
    print(f"Open http://{a.host}:{a.port}")
    app.run(host=a.host, port=a.port, threaded=True, debug=False)


if __name__ == "__main__":
    main()
