"""
Folder indexer. Walks a directory tree, records filesystem metadata for every file and
folder, stores every line of text (and text recovered from binary artifacts) in SQLite
with an FTS5 trigram index, and runs line-, file- and case-level analysis.
"""
import csv
import functools
import gzip
import heapq
import json
import os
import re
import sqlite3
import stat
import threading
import time
from datetime import datetime
from urllib.parse import unquote

import analyzers as az
import artifacts as art
import linux
import triage
import webaccess
import toolhunt
import intel
import corroboration
import fsweep

SCHEMA_VERSION = "4"
BATCH = 5000
MAX_LINE_CHARS = 100_000
MAX_ENTITY_LINES = 50
MAX_FINDINGS_PER_RULE = 1000
PRETTY_JSON_MAX_BYTES = 50 * 1024 * 1024
MAX_RECORD_IDS = 2_000_000
DEFAULT_EXCLUDE_DIRS = {".git", ".svn", ".hg", "__pycache__", "node_modules", ".venv", "venv", ".idea"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS files(
    id INTEGER PRIMARY KEY, path TEXT UNIQUE, rel TEXT, name TEXT, ext TEXT, size INTEGER,
    mtime REAL, mtime_ns INTEGER, ctime_ns INTEGER, atime_ns INTEGER, birth_ns INTEGER,
    inode INTEGER, mode INTEGER, uid INTEGER, gid INTEGER, sha256 TEXT, md5 TEXT, magic TEXT, entropy REAL, nul_bytes INTEGER,
    line_count INTEGER DEFAULT 0, first_ts TEXT, last_ts TEXT, ts_count INTEGER DEFAULT 0,
    encoding TEXT, kind TEXT, status TEXT, note TEXT, integrity TEXT, indexed_at TEXT);
CREATE TABLE IF NOT EXISTS fsnodes(
    id INTEGER PRIMARY KEY, rel TEXT, type TEXT, target TEXT, mode INTEGER, uid INTEGER, gid INTEGER,
    mtime_ns INTEGER, ctime_ns INTEGER);
CREATE TABLE IF NOT EXISTS dirs(
    id INTEGER PRIMARY KEY, rel TEXT, mtime_ns INTEGER, ctime_ns INTEGER, birth_ns INTEGER, entries INTEGER);
CREATE TABLE IF NOT EXISTS lines(
    id INTEGER PRIMARY KEY, file_id INTEGER, line_no INTEGER, ts TEXT, text TEXT);
CREATE INDEX IF NOT EXISTS idx_lines_file ON lines(file_id, line_no);
CREATE INDEX IF NOT EXISTS idx_lines_ts ON lines(ts) WHERE ts IS NOT NULL;
CREATE TABLE IF NOT EXISTS entities(
    id INTEGER PRIMARY KEY, type TEXT, value TEXT, meta TEXT, UNIQUE(type, value));
CREATE TABLE IF NOT EXISTS entity_files(
    entity_id INTEGER, file_id INTEGER, hits INTEGER, first_line INTEGER, lines TEXT);
CREATE INDEX IF NOT EXISTS idx_ef_entity ON entity_files(entity_id);
CREATE INDEX IF NOT EXISTS idx_ef_file ON entity_files(file_id);
CREATE TABLE IF NOT EXISTS findings(
    id INTEGER PRIMARY KEY, rule TEXT, severity TEXT, category TEXT, scope TEXT,
    file_id INTEGER, line_no INTEGER, ts TEXT, ts_end TEXT, snippet TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS idx_findings_file ON findings(file_id, line_no);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule);
CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings(ts);
CREATE INDEX IF NOT EXISTS idx_findings_cat ON findings(category);
CREATE TABLE IF NOT EXISTS facts(
    id INTEGER PRIMARY KEY, kind TEXT, scope TEXT, file_id INTEGER, line_no INTEGER, ts TEXT, subject TEXT, data TEXT);
CREATE INDEX IF NOT EXISTS idx_facts_kind ON facts(kind, ts);
CREATE INDEX IF NOT EXISTS idx_facts_file ON facts(file_id);
CREATE TABLE IF NOT EXISTS decoded(
    id INTEGER PRIMARY KEY, file_id INTEGER, line_no INTEGER, method TEXT, text TEXT);
CREATE INDEX IF NOT EXISTS idx_decoded_file ON decoded(file_id, line_no);
CREATE TABLE IF NOT EXISTS pins(
    id INTEGER PRIMARY KEY, rel TEXT, line_no INTEGER, text TEXT, note TEXT, created TEXT);
"""
DATA_TABLES = ("files", "dirs", "fsnodes", "lines", "lines_fts", "entities", "entity_files", "findings", "facts", "finding_verdicts",
               "decoded", "decoded_fts")


@functools.lru_cache(maxsize=64)
def _rx(pattern):
    return re.compile(pattern)


def _regexp(pattern, value):
    if value is None:
        return 0
    try:
        return 1 if _rx(pattern).search(value) else 0
    except re.error:
        return 0


def connect(db_path):
    con = sqlite3.connect(db_path, timeout=60, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.execute("PRAGMA cache_size=-65536")
    con.execute("PRAGMA temp_store=MEMORY")
    con.create_function("REGEXP", 2, _regexp, deterministic=True)
    return con


def trigram_supported(con):
    try:
        con.execute("CREATE VIRTUAL TABLE temp._tri USING fts5(x, tokenize='trigram')")
        con.execute("DROP TABLE temp._tri")
        return True
    except sqlite3.OperationalError:
        return False


def init_db(con):
    """Create tables; databases from an older version are cleared (pins are kept)."""
    has_meta = con.execute("SELECT 1 FROM sqlite_master WHERE name='meta'").fetchone()
    has_files = con.execute("SELECT 1 FROM sqlite_master WHERE name='files'").fetchone()
    ver = con.execute("SELECT value FROM meta WHERE key='schema'").fetchone() if has_meta else None
    if has_files and (not ver or ver[0] != SCHEMA_VERSION):
        for t in DATA_TABLES:
            con.execute(f"DROP TABLE IF EXISTS {t}")
        con.execute("DELETE FROM meta WHERE key IN ('root', 'last_indexed')")
        con.commit()
    con.executescript(SCHEMA)
    triage.ensure(con)
    fts = trigram_supported(con)
    if fts:
        con.execute("CREATE VIRTUAL TABLE IF NOT EXISTS lines_fts USING fts5("
                    "text, content='lines', content_rowid='id', tokenize='trigram')")
        con.execute("CREATE VIRTUAL TABLE IF NOT EXISTS decoded_fts USING fts5("
                    "text, content='decoded', content_rowid='id', tokenize='trigram')")
    set_meta(con, "fts", "1" if fts else "0")
    set_meta(con, "schema", SCHEMA_VERSION)
    con.commit()
    return fts


def get_meta(con, key, default=None):
    row = con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def set_meta(con, key, value):
    con.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (key, str(value)))


# --------------------------------------------------------------- helpers ---
def _ext(name):
    """Extension, ignoring log-rotation numbers: access.log.1 -> .log, auth.log.2.gz -> .log.gz"""
    low = name.lower()
    gz = next((c for c in (".gz", ".bz2", ".xz") if low.endswith(c)), None)
    if gz:
        low = low[:-len(gz)]
    parts = low.split(".")[1:]
    while parts and parts[-1].isdigit():
        parts.pop()
    ext = ("." + parts[-1]) if parts else ""
    if gz:
        return (ext or "") + gz
    return ext or "(none)"


def stat_info(st):
    """Portable MAC(B) times. On Windows st_ctime is creation time, so it goes to birth."""
    birth = getattr(st, "st_birthtime_ns", None)
    if birth is None and hasattr(st, "st_birthtime"):
        birth = int(st.st_birthtime * 1e9)
    if os.name == "nt":
        change = None
        if birth is None:
            birth = st.st_ctime_ns
    else:
        change = st.st_ctime_ns
    return {"size": st.st_size, "mtime": st.st_mtime, "mtime_ns": st.st_mtime_ns, "ctime_ns": change,
            "atime_ns": st.st_atime_ns, "birth_ns": birth, "inode": st.st_ino, "mode": st.st_mode,
            "uid": getattr(st, "st_uid", None), "gid": getattr(st, "st_gid", None)}


def ns_ts(ns):
    return az.epoch_to_ts(ns / 1e9) if ns else None


def _dur(sec):
    sec = int(abs(sec))
    if sec < 120:
        return f"{sec} s"
    if sec < 7200:
        return f"{sec // 60} min"
    if sec < 172800:
        return f"{sec / 3600:.1f} h"
    return f"{sec / 86400:.1f} days"


def purge_invalid_entities(con):
    """Drop stored entities that fail today's plausibility checks (e.g. junk Windows paths
    extracted by older versions), so existing databases are cleaned without re-indexing."""
    bad = [r[0] for r in con.execute("SELECT id, type, value FROM entities WHERE type IN (%s)"
                                     % ",".join("?" * len(az.ENTITY_VALIDATORS)), list(az.ENTITY_VALIDATORS))
           if not az.ENTITY_VALIDATORS[r[1]](r[2])]
    for i in range(0, len(bad), 500):
        chunk = bad[i:i + 500]
        ph = ",".join("?" * len(chunk))
        con.execute(f"DELETE FROM entity_files WHERE entity_id IN ({ph})", chunk)
        con.execute(f"DELETE FROM entities WHERE id IN ({ph})", chunk)
    con.commit()
    return len(bad)


def seq_gaps(ids):
    """Missing ranges in a numeric sequence, or [] if it does not look like one contiguous series."""
    s = sorted(ids)
    if len(s) < 10:
        return []
    span = s[-1] - s[0] + 1
    if span == len(s):
        return []
    gaps = [(a, b) for a, b in zip(s, s[1:]) if b - a > 1]
    if len(s) / span < 0.5 or len(gaps) > 50:
        return []  # filtered export or unrelated numbers: not evidence of removal
    return sorted(gaps, key=lambda g: g[0] - g[1])[:20]


# ------------------------------------------------------------------ indexer ---
class Indexer:
    def __init__(self, db_path):
        self.db_path = os.path.abspath(db_path)
        self._lock = threading.Lock()
        self._thread = None
        self._cancel = False
        self.fts = True
        self.state = {"running": False, "phase": "idle", "message": "Not indexed yet"}

    # public -----------------------------------------------------------------
    def start(self, root, full=False, max_mb=200, exclude=None):
        root = os.path.abspath(os.path.expanduser(root))
        if not os.path.isdir(root):
            raise ValueError(f"Folder not found: {root}")
        with self._lock:
            if self.state.get("running"):
                return False
            self._cancel = False
            self.state = {
                "running": True, "phase": "scanning", "root": root, "full": full,
                "files_total": 0, "files_done": 0, "files_skipped": 0, "bytes_total": 0,
                "bytes_done": 0, "lines": 0, "errors": [], "current": "",
                "started": time.time(), "finished": None, "message": "Scanning folder",
            }
            excl = set(DEFAULT_EXCLUDE_DIRS) | set(exclude or [])
            self._thread = threading.Thread(
                target=self._run, args=(root, full, max_mb * 1024 * 1024, excl), daemon=True)
            self._thread.start()
        return True

    def cancel(self):
        self._cancel = True

    def status(self):
        s = dict(self.state)
        s["errors"] = list(s.get("errors", []))[-20:]
        if s.get("running") and s.get("bytes_total"):
            s["progress"] = round(100 * s.get("bytes_done", 0) / max(1, s["bytes_total"]), 1)
        return s

    # worker ---------------------------------------------------------------
    def _run(self, root, full, max_bytes, exclude):
        con = connect(self.db_path)
        st = self.state
        try:
            self.fts = init_db(con)
            intel.ensure(con)
            if get_meta(con, "root") != root:
                full = True
            if full:
                st["message"] = "Clearing previous index"
                self._wipe(con)
            set_meta(con, "root", root)
            con.commit()

            db_files = {self.db_path, self.db_path + "-wal", self.db_path + "-shm", self.db_path + "-journal"}
            found, dirs, nodes = {}, [], []
            # stat everything before any file is opened, so access times are captured as found
            for dirpath, dirnames, filenames in os.walk(root):
                if os.path.normpath(dirpath) == os.path.normpath(root):
                    # a full filesystem dump: pseudo-filesystems hold nothing from the original disk
                    if os.path.isdir(os.path.join(root, "var", "lib", "dpkg")):
                        dirnames[:] = [d for d in dirnames if d not in ("proc", "sys")]
                try:
                    dst = os.stat(dirpath)
                    di = stat_info(dst)
                    dirs.append((os.path.relpath(dirpath, root).replace(os.sep, "/"), di["mtime_ns"],
                                 di["ctime_ns"], di["birth_ns"], len(dirnames) + len(filenames)))
                except OSError:
                    pass
                dirnames[:] = sorted(d for d in dirnames if d not in exclude
                                     and os.path.join(dirpath, d) != self.db_path + ".extracted")
                for fn in sorted(filenames) + sorted(d for d in dirnames if os.path.islink(os.path.join(dirpath, d))):
                    p = os.path.join(dirpath, fn)
                    if p in db_files:
                        continue
                    try:
                        lst = os.lstat(p)
                    except OSError as e:
                        st["errors"].append(f"{p}: {e}")
                        continue
                    if not stat.S_ISREG(lst.st_mode):
                        # symlinks, devices, pipes and sockets are evidence too (history -> /dev/null,
                        # a device node in /tmp), but must never be opened
                        typ = ("symlink" if stat.S_ISLNK(lst.st_mode) else "dir" if stat.S_ISDIR(lst.st_mode)
                               else "char" if stat.S_ISCHR(lst.st_mode) else "block" if stat.S_ISBLK(lst.st_mode)
                               else "fifo" if stat.S_ISFIFO(lst.st_mode) else "socket" if stat.S_ISSOCK(lst.st_mode)
                               else "other")
                        if typ == "dir":
                            continue
                        try:
                            tgt = os.readlink(p) if typ == "symlink" else None
                        except OSError:
                            tgt = None
                        nodes.append((os.path.relpath(p, root).replace(os.sep, "/"), typ, tgt, lst.st_mode,
                                      lst.st_uid, lst.st_gid, lst.st_mtime_ns, lst.st_ctime_ns))
                        continue
                    found[p] = stat_info(lst)
                if self._cancel:
                    break
            con.execute("DELETE FROM fsnodes")
            con.executemany("INSERT INTO fsnodes(rel, type, target, mode, uid, gid, mtime_ns, ctime_ns) "
                            "VALUES(?,?,?,?,?,?,?,?)", nodes)
            # files that exactly match their Debian package need no line index (most of /usr on a full dump)
            self.pristine = fsweep.dpkg_md5_map(root, found)
            self._expand_archives(root, found, max_bytes, st)
            con.execute("DELETE FROM dirs")
            con.executemany("INSERT INTO dirs(rel, mtime_ns, ctime_ns, birth_ns, entries) VALUES(?,?,?,?,?)", dirs)

            existing = {r["path"]: r for r in con.execute("SELECT id, path, size, mtime_ns, status FROM files")}
            removed = [r["id"] for p, r in existing.items() if p not in found]
            todo = []
            for p, info in found.items():
                r = existing.get(p)
                if r and r["size"] == info["size"] and r["mtime_ns"] == info["mtime_ns"] and \
                        r["status"] in ("ok", "binary", "skipped", "empty", "zero", "pristine", "archive"):
                    continue
                todo.append((p, info))

            st.update(phase="indexing", files_total=len(todo), bytes_total=sum(t[1]["size"] for t in todo),
                      files_unchanged=len(found) - len(todo), files_removed=len(removed),
                      message=f"Indexing {len(todo)} files")
            for fid in removed:
                self._purge(con, fid)
            con.commit()

            for p, info in todo:
                if self._cancel:
                    st["message"] = "Cancelled"
                    break
                st["current"] = self.virtual.get(p) or os.path.relpath(p, root)
                try:
                    self._index_file(con, root, p, info, max_bytes)
                except Exception as e:  # keep going on any single-file failure
                    con.rollback()
                    st["errors"].append(f"{st['current']}: {e}")
                st["files_done"] += 1
                st["bytes_done"] += info["size"]
            con.commit()

            st.update(phase="finalizing", message="Analysing the case as a whole")
            con.execute("DELETE FROM entities WHERE id NOT IN (SELECT DISTINCT entity_id FROM entity_files)")
            purge_invalid_entities(con)
            self._analyze_case(con)
            triage.apply(con)  # your verdicts carry over to the new findings
            corroboration.build(con)
            corroboration.invalidate()
            if full and self.fts:
                st["message"] = "Optimizing search index"
                con.execute("INSERT INTO lines_fts(lines_fts) VALUES('optimize')")
            set_meta(con, "last_indexed", datetime.now().isoformat(timespec="seconds"))
            con.commit()
            if not self._cancel:
                took = time.time() - st["started"]
                st["message"] = (f"Indexed {st['files_done']} changed files, "
                                 f"{st['lines']:,} lines in {took:.1f}s")
        except Exception as e:
            st["errors"].append(str(e))
            st["message"] = f"Indexing failed: {e}"
        finally:
            st.update(running=False, phase="idle", current="", finished=time.time())
            con.close()

    def _expand_archives(self, root, found, max_bytes, st):
        """Unpack tar / tar.gz / tar.xz / tar.bz2 / zip found in the evidence into a cache next to the database
        (never into the evidence). Members are indexed as '<archive>!/<path inside>' with their own times."""
        import hashlib
        self.virtual, self.archives = {}, {}
        cache = self.db_path + ".extracted"
        used = set()
        queue = [(p, None) for p in found]
        level = {p: 0 for p in found}
        st["message"] = "Looking for archives"
        while queue:
            p, _x = queue.pop(0)
            info = found[p]
            rel = self.virtual.get(p) or os.path.relpath(p, root).replace(os.sep, "/")
            if level[p] > 1 or info["size"] < 22 or rel in getattr(self, "pristine", {}):
                continue
            kind = art.archive_kind(p, rel.rsplit("/", 1)[-1])
            if not kind:
                continue
            key = hashlib.sha1(rel.encode("utf-8", "replace")).hexdigest()[:20]
            used.add(key)
            st["message"] = f"Unpacking {rel}"
            try:
                members, sm = art.expand_archive(p, kind, os.path.join(cache, key), max_bytes)
            except Exception as e:  # one bad archive must not stop indexing
                st["errors"].append(f"{rel}: could not unpack ({e})")
                continue
            self.archives[p] = sm
            for mpath, inner in members:
                try:
                    found[mpath] = stat_info(os.lstat(mpath))
                except OSError:
                    continue
                self.virtual[mpath] = f"{rel}!/{inner}"
                level[mpath] = level[p] + 1
                queue.append((mpath, None))
        if os.path.isdir(cache):
            for d in os.listdir(cache):
                if d not in used:
                    import shutil
                    shutil.rmtree(os.path.join(cache, d), ignore_errors=True)

    def _wipe(self, con):
        for t in ("lines", "files", "entities", "entity_files", "findings", "dirs", "facts", "decoded", "finding_verdicts"):
            con.execute(f"DELETE FROM {t}")
        if self.fts:
            con.execute("INSERT INTO lines_fts(lines_fts) VALUES('delete-all')")
            con.execute("INSERT INTO decoded_fts(decoded_fts) VALUES('delete-all')")

    def _purge(self, con, file_id):
        if self.fts:
            con.execute("INSERT INTO lines_fts(lines_fts, rowid, text) "
                        "SELECT 'delete', id, text FROM lines WHERE file_id=?", (file_id,))
        con.execute("DELETE FROM lines WHERE file_id=?", (file_id,))
        if self.fts:
            con.execute("INSERT INTO decoded_fts(decoded_fts, rowid, text) "
                        "SELECT 'delete', id, text FROM decoded WHERE file_id=?", (file_id,))
        con.execute("DELETE FROM decoded WHERE file_id=?", (file_id,))
        con.execute("DELETE FROM facts WHERE file_id=?", (file_id,))
        con.execute("DELETE FROM entity_files WHERE file_id=?", (file_id,))
        con.execute("DELETE FROM findings WHERE file_id=?", (file_id,))
        con.execute("DELETE FROM files WHERE id=?", (file_id,))

    # one file ---------------------------------------------------------------
    def _index_file(self, con, root, path, info, max_bytes):
        st = self.state
        old = con.execute("SELECT id FROM files WHERE path=?", (path,)).fetchone()
        if old:
            self._purge(con, old["id"])
        rel = getattr(self, "virtual", {}).get(path) or os.path.relpath(path, root).replace(os.sep, "/")
        name = rel.rsplit("/", 1)[-1]
        cur = con.execute(
            "INSERT INTO files(path, rel, name, ext, size, mtime, mtime_ns, ctime_ns, atime_ns, birth_ns, inode, mode, "
            "uid, gid, status, indexed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'indexing', ?)",
            (path, rel, name, _ext(name), info["size"], info["mtime"], info["mtime_ns"], info["ctime_ns"],
             info["atime_ns"], info["birth_ns"], info["inode"], info["mode"], info.get("uid"), info.get("gid"),
             datetime.now().isoformat(timespec="seconds")))
        fid = cur.lastrowid
        mtime_ts = ns_ts(info["mtime_ns"])
        ff = []  # file-level findings: (rule, line_no, ts, ts_end, snippet, detail)
        integrity = {}

        def finish(status, note=None, lines=0, enc=None, kind=None, stats=None):
            stats = stats or {}
            con.execute(
                "UPDATE files SET status=?, note=?, line_count=?, encoding=?, kind=?, first_ts=?, last_ts=?, "
                "ts_count=?, integrity=? WHERE id=?",
                (status, note, lines, enc, kind, stats.get("first_ts"), stats.get("last_ts"),
                 stats.get("ts_count", 0), json.dumps(integrity) if integrity else None, fid))
            self._insert_file_findings(con, fid, ff)
            # commit in batches: a full filesystem dump is mostly binaries and verified package files
            self._uncommitted = getattr(self, "_uncommitted", 0) + 1
            if lines or self._uncommitted >= 250:
                con.commit()
                self._uncommitted = 0

        if info["size"] > max_bytes:
            st["files_skipped"] += 1
            return finish("skipped", f"larger than {max_bytes // (1024 * 1024)} MB limit")

        p = art.profile_file(path)
        kind, enc, mkind, mlabel = art.classify(p, name)
        con.execute("UPDATE files SET sha256=?, md5=?, magic=?, entropy=?, nul_bytes=? WHERE id=?",
                    (p["sha256"], p.get("md5"), mlabel, p["entropy"], p["nul_bytes"], fid))
        lkind = linux.path_kind(rel)
        if lkind in linux.BINARY_KINDS and kind in ("binary", "text", "zero"):
            kind = lkind
        if p["error"]:
            return finish("error", p["error"])
        sm = getattr(self, "archives", {}).get(path)
        if p.get("truncated") and not (sm and sm.get("truncated")):
            ff.append(("compressed_truncated", None, mtime_ts, None,
                       f"{p['compression']} data ends early or is damaged: {p['decoded_size']:,} bytes recovered "
                       f"and indexed ({p.get('compress_error') or 'truncated'}). Last modified {mtime_ts}", None))
        if sm:
            if sm.get("escaping"):
                ff.append(("archive_path_escape", None, mtime_ts, None,
                           f"{len(sm['escaping'])} member name(s) point outside the folder it unpacks into: "
                           + ", ".join(sm["escaping"][:6]), json.dumps(sm["escaping"])))
            if sm.get("truncated"):
                ff.append(("archive_truncated", None, mtime_ts, None,
                           f"{sm['extracted']:,} file(s) recovered before the archive ended or broke: "
                           f"{sm.get('error') or 'truncated'}", None))
            return finish("archive", art.archive_note(sm), kind="archive")
        want = getattr(self, "pristine", {}).get(rel)
        if want and p.get("md5") == want and "/etc/" not in "/" + rel:
            return finish("pristine", "identical to the file its Debian package installed; content not indexed",
                          kind=kind)

        # --- content checks that do not need the lines
        ext = _ext(name).replace(".gz", "") or ""
        if kind == "empty":
            ff.append(("empty_file", None, mtime_ts, None, f"0 bytes, last modified {mtime_ts}", None))
            return finish("empty", "empty file", kind=kind)
        if kind == "zero" and lkind != "utmp":
            ff.append(("all_zero", None, mtime_ts, None,
                       f"{p['decoded_size']:,} bytes, all NUL. Last modified {mtime_ts}", None))
            return finish("zero", "entirely NUL bytes", kind=kind)
        if mlabel and mkind not in ("gzip", "recycle", "unknown") and (ext in az.TEXT_LIKE_EXT or
                                                  (ext in art.EXT_EXPECTS and mkind not in art.EXT_EXPECTS[ext])):
            ff.append(("magic_mismatch", None, mtime_ts, None, f"named {ext} but the content is {mlabel}", None))
        if mkind == "openssl":
            ff.append(("openssl_encrypted", None, mtime_ts, None, f"starts with 'Salted__' ({mlabel})", None))
        if az.RANSOM_EXT_RX.search(name):
            ff.append(("ransom_extension", None, mtime_ts, None, name, None))
        if ext in az.TEXT_LIKE_EXT and kind == "binary" and (p["entropy"] or 0) > 7.2:
            ff.append(("high_entropy_text", None, mtime_ts, None,
                       f"entropy {p['entropy']:.2f} bits/byte in a {ext} file", None))

        year = datetime.fromtimestamp(info["mtime"]).year
        ref = info["mtime"]
        lines_iter, continuity, status_note = None, True, None

        if kind == "text":
            if p["nul_bytes"]:
                status_note = f"{p['nul_bytes']:,} NUL bytes in {p['nul_region_count']} region(s)"
            if name.lower().endswith(".json") and info["size"] <= PRETTY_JSON_MAX_BYTES:
                with self._open_text(path, enc) as fh:
                    raw = fh.read().replace("\x00", "")
                if raw.count("\n") < 3 and len(raw) > 1000:
                    try:
                        raw = json.dumps(json.loads(raw), indent=2, ensure_ascii=False)
                        status_note = "minified JSON pretty-printed for indexing"
                    except ValueError:
                        pass
                lines_iter = iter(raw[:-1].split("\n") if raw.endswith("\n") else raw.split("\n"))
        elif kind == "evtx":
            reader = art.EvtxReader(path)
            lines_iter = reader.lines()
            status_note = "Windows event log: record IDs, times and text strings (binary XML not decoded)"
        elif kind == "sqlite":
            lines_iter = art.sqlite_lines(path)
            continuity = False
            status_note = "SQLite: one line per table row, time columns converted to UTC"
        elif kind == "recycle":
            data = art.read_decoded(path)
            r = art.parse_recycle_i(data)
            ff.append(("recycle_bin", 1, r["deleted"], None,
                       f"{r['path']} ({r['size']:,} bytes) deleted {r['deleted']} UTC", json.dumps(r)))
            lines_iter = iter([f"Recycle Bin: {r['path']} | size {r['size']} | deleted {r['deleted']} UTC"])
            status_note = "Recycle Bin $I record"
        elif kind == "vimswap":
            data = art.read_decoded(path, 1024)
            r = art.parse_vim_swap(data)
            ff.append(("vim_swap", 1, mtime_ts, None,
                       f"{r['user']}@{r['host']} was editing {r['file']} (pid {r['pid']}); swap last written {mtime_ts}",
                       json.dumps(r)))
            lines_iter = iter([f"Vim swap: user={r['user']} host={r['host']} pid={r['pid']} file={r['file']} "
                               f"file_mtime={r['mtime']} swap_mtime={mtime_ts}"])
            continuity = False
            status_note = "Vim swap file header"
        elif kind in ("utmp", "lastlog"):
            reader = (linux.UtmpReader if kind == "utmp" else linux.LastlogReader)(path, rel)
            lines_iter = reader.lines()
            continuity = False
            status_note = "login records (binary): one line per record" if kind == "utmp" else "lastlog: last login per UID"
        elif kind == "localtime":
            tz = linux.tz_from_tzif(path)
            lines_iter = iter([f"TZ={tz or 'unknown'}"])
            continuity = False
            status_note = "time zone of the system"
        elif kind == "pcap":
            reader = linux.pcap.PcapReader(path, rel)
            lines_iter = reader.lines()
            continuity = False
            status_note = "packet capture: one line per packet, times from the capture (UTC)"
        elif kind == "binary":
            if mkind in art.STRINGS_OK and (p["entropy"] or 0) < 7.2:
                big = info["size"] > 4 * 1024 * 1024
                lines_iter = art.binary_strings(path, max_lines=40_000 if big else 200_000)
                continuity = False
                status_note = f"{mlabel or 'Binary'}: printable strings with byte offsets" + \
                    (" (first 40,000 strings of a large program)" if big else "")
            else:
                st["files_skipped"] += 1
                integrity["profile"] = {"entropy": p["entropy"], "magic": mlabel}
                return finish("binary", f"{mlabel or 'binary'} content not indexed", kind=kind)

        if lines_iter is None:
            lines_iter = self._open_text(path, enc)
        watch = sorted({r["line"] for r in p["nul_regions"][:50]}) if kind == "text" else []
        host = None
        if kind in ("utmp", "lastlog"):
            host = reader.hf
        elif kind == "pcap":
            host = linux.HostFile("pcap", rel, mtime_ts)
            reader.hf = host
        elif kind == "localtime":
            host = linux.HostFile("localtime", rel, mtime_ts)
            host.fact("host", 1, None, "tz_rule", value=linux.tz_from_tzif(path) or "")
        elif lkind and lkind not in linux.BINARY_KINDS:
            host = linux.HostFile(lkind, rel, mtime_ts)
        try:
            stats = self._ingest(con, fid, lines_iter, year, ref, continuity, watch, name,
                                 host=None if kind in ("utmp", "lastlog", "localtime", "pcap") else host,
                                 quiet=lkind in linux.QUIET_KINDS, rel=rel)
        finally:
            if hasattr(lines_iter, "close"):
                lines_iter.close()
        if kind == "pcap":
            reader.finish()
        if host:
            if kind != "pcap":
                host.finish()
            ff.extend(host.findings)
            for rule, ln, *_ in host.findings:
                dup = linux.SUPERSEDES.get(rule)
                if dup and ln:
                    con.execute("DELETE FROM findings WHERE file_id=? AND line_no=? AND rule IN (%s)" % ",".join("?" * len(dup)),
                                (fid, ln, *dup))
            con.executemany("INSERT INTO facts(kind, scope, file_id, line_no, ts, subject, data) VALUES(?,?,?,?,?,?,?)",
                            [(k, "file", fid, n, t, subj, json.dumps(d)) for k, n, t, subj, d in host.facts])
            self._insert_decoded(con, fid, host.decoded)
            if kind == "utmp":
                integrity["utmp"] = reader.info

        # --- file-level analysis from what the lines told us
        integrity.update(stats.pop("integrity"))
        for r in (p["nul_regions"][:50] if kind == "text" else []):
            before, after = stats["watch"].get(r["line"], (None, None))
            if r["offset"] == 0:
                ff.append(("nul_truncation", r["line"], after or mtime_ts, None,
                           f"first {r['length']:,} bytes are NUL: the file was emptied while still open for writing; "
                           f"writing resumed {('at ' + after) if after else 'afterwards'}", json.dumps(r)))
            else:
                when = f"between {before} and {after}" if before and after else (f"after {before}" if before else "")
                ff.append(("nul_region", r["line"], before, after,
                           f"{r['length']:,} NUL bytes at offset {r['offset']:,} near line {r['line']} {when}",
                           json.dumps(r)))
        if p["nul_regions"] and kind == "text":
            integrity["nul_regions"] = p["nul_regions"][:50]
            integrity["nul_region_count"] = p["nul_region_count"]
        ff.extend(stats.pop("findings"))
        if kind == "evtx":
            integrity["evtx"] = reader.info
            if reader.info["dirty"]:
                ff.append(("evtx_dirty", None, mtime_ts, None,
                           "header flag says the log was not closed cleanly (copied live, or edited)", None))

        last_e = az.ts_to_epoch(stats["last_ts"]) if stats.get("last_ts") else None
        if continuity and last_e and stats["ts_count"] >= 20 and kind != "sqlite":
            if last_e > info["mtime"] + 86400:
                ff.append(("entries_after_mtime", None, stats["last_ts"], None,
                           f"latest entry {stats['last_ts']} is {_dur(last_e - info['mtime'])} after the file's "
                           f"modified time {mtime_ts} UTC: the modified time was likely set back", None))
            elif info["mtime"] > last_e + 7 * 86400:
                ff.append(("edited_after_entries", None, stats["last_ts"], mtime_ts,
                           f"last entry {stats['last_ts']}, but modified {mtime_ts} UTC ({_dur(info['mtime'] - last_e)} later)",
                           None))
        if name.lower().endswith(".trashinfo"):
            self._trashinfo(path, ff)

        status = "partial" if self._cancel else "ok"
        finish(status, status_note if status == "ok" else "indexing was cancelled part-way",
               stats["n"], enc, kind, stats)

    @staticmethod
    def _open_text(path, enc):
        return art.open_decoded_text(path, enc)

    @staticmethod
    def _trashinfo(path, ff):
        try:
            txt = open(path, encoding="utf-8", errors="replace").read(8192)
        except OSError:
            return
        mp = re.search(r"(?m)^Path=(.*)$", txt)
        md = re.search(r"(?m)^DeletionDate=(.*)$", txt)
        when = az.parse_timestamp(md.group(1)) if md else None
        orig = unquote(mp.group(1).strip()) if mp else "?"
        ff.append(("trash_info", 2 if md else None, when, None, f"{orig} moved to Trash {when or ''}", None))

    def _insert_decoded(self, con, fid, rows):
        if not rows:
            return
        first = None
        for n, method, text in rows:
            cur = con.execute("INSERT INTO decoded(file_id, line_no, method, text) VALUES(?,?,?,?)",
                              (fid, n, method, text[:20000]))
            first = first or cur.lastrowid
        if self.fts:
            con.execute("INSERT INTO decoded_fts(rowid, text) SELECT id, text FROM decoded WHERE file_id=? AND id>=?",
                        (fid, first))

    def _insert_file_findings(self, con, fid, ff):
        rows = []
        for rule, line_no, ts, ts_end, snippet, detail in ff:
            ri = az.RULE_INFO[rule]
            rows.append((rule, ri["severity"], ri["category"], "file", fid, line_no, ts, ts_end, snippet[:600], detail))
        con.executemany("INSERT INTO findings(rule, severity, category, scope, file_id, line_no, ts, ts_end, snippet, detail) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?)", rows)

    # lines ------------------------------------------------------------------
    def _ingest(self, con, fid, it, year, ref, continuity, watch, name, host=None, quiet=False, rel=None):
        st = self.state
        ents, findings, file_findings, rule_counts, batch = {}, [], [], {}, []
        decoded_rows = []
        rec_ids = {"event": {}, "audit": {}}
        watch_set, watch_res, waiting = set(watch), {}, []
        gaps, backs = [], []   # heaps
        n_back = 0
        prev_e = prev_ts = prev_line = None
        first_ts = last_ts = None
        min_e = max_e = None
        ts_count = 0
        hist_ts = None
        mft_cols = None
        n = 0
        for n, item in enumerate(it, 1):
            if isinstance(item, tuple):
                line, ts = item
            else:
                line, ts = item, None
            if "\x00" in line:
                line = line.replace("\x00", "")
            line = line.rstrip("\r\n")
            if len(line) > MAX_LINE_CHARS:
                line = line[:MAX_LINE_CHARS]
            if ts is None and line:
                m = az.HIST_TS.match(line)
                if m:
                    ts = hist_ts = az.epoch_to_ts(int(m.group(1)))
                else:
                    ts = az.line_timestamp(line, year, ref)
                    if ts is None and hist_ts:
                        ts, hist_ts = hist_ts, None
            if n in watch_set:
                watch_res[n] = [last_ts, None]
                waiting.append(n)
            if ts:
                ts_count += 1
                for w in waiting:
                    watch_res[w][1] = ts
                waiting = []
                e = az.ts_to_epoch(ts)
                if e is not None:
                    if first_ts is None:
                        first_ts = ts
                    if min_e is None or e < min_e:
                        min_e = e
                    if max_e is None or e > max_e:
                        max_e, last_ts = e, ts
                    if continuity and prev_e is not None:
                        d = e - prev_e
                        if d < -300:
                            n_back += 1
                            item_ = (-d, prev_line, n, prev_ts, ts)
                            if len(backs) < 50:
                                heapq.heappush(backs, item_)
                            else:
                                heapq.heappushpop(backs, item_)
                        elif d > 1800:
                            item_ = (d, prev_line, n, prev_ts, ts)
                            if len(gaps) < 100:
                                heapq.heappush(gaps, item_)
                            else:
                                heapq.heappushpop(gaps, item_)
                    if prev_e is None or e >= prev_e:
                        prev_e, prev_ts, prev_line = e, ts, n
            batch.append((fid, n, ts, line))
            if host is not None:
                host.feed(n, line, ts)
            if line and not quiet:
                for etype, val, meta in az.extract_entities(line):
                    ent = ents.get((etype, val))
                    if ent is None:
                        ents[(etype, val)] = [meta, 1, n, [n]]
                    else:
                        ent[1] += 1
                        if len(ent[3]) < MAX_ENTITY_LINES:
                            ent[3].append(n)
                fired = set()
                for rid, sev, snip in az.run_rules(line):
                    fired.add(rid)
                    c = rule_counts.get(rid, 0)
                    if c < MAX_FINDINGS_PER_RULE:
                        ri = az.RULE_INFO[rid]
                        findings.append((rid, sev, ri["category"], "line", fid, n, ts, None, snip, None))
                    rule_counts[rid] = c + 1
                if fired & az._OBF_RULES or az._ENCODED_HINT.search(line[:az.MAX_ANALYZE_CHARS]):
                    decs = az.decode_candidates(line)[:6]
                    seen_r = set()
                    for d in decs:
                        if len(decoded_rows) < 200000:
                            decoded_rows.append((n, d["method"], d["output"]))
                        for rid, sev, snip in az.run_rules(d["output"]):
                            if rid in az._OBF_RULES or rid in seen_r:
                                continue
                            seen_r.add(rid)
                            c = rule_counts.get(rid, 0)
                            if c < MAX_FINDINGS_PER_RULE:
                                ri = az.RULE_INFO[rid]
                                findings.append((rid, sev, ri["category"], "line", fid, n, ts, None,
                                                 f"hidden in {d['method']}: {snip}", '{"hidden": true}'))
                            rule_counts[rid] = c + 1
                low = line[:300].lower()
                if ("record" in low or "audit(" in low):
                    m = az.RECORD_ID_RX.search(line)
                    if m:
                        bucket = rec_ids["event"] if m.group(1) else rec_ids["audit"]
                        if len(bucket) < MAX_RECORD_IDS:
                            rid_ = int(m.group(1) or m.group(2))
                            if rid_ not in bucket:
                                bucket[rid_] = (n, ts)
                # MFTECmd-style CSV: SI<FN and uSecZeros columns
                if n == 1 and "," in line and ("SI<FN" in line or "uSecZeros" in line):
                    hdr = next(csv.reader([line]))
                    lc = [h.strip().lower() for h in hdr]
                    idx = lambda k: lc.index(k.lower()) if k.lower() in lc else None
                    mft_cols = {"si": idx("SI<FN"), "usec": idx("uSecZeros"), "name": idx("FileName"),
                                "parent": idx("ParentPath"), "c10": idx("Created0x10"), "c30": idx("Created0x30"),
                                "m10": idx("LastModified0x10")}
                elif mft_cols and "True" in line:
                    self._mft_row(line, n, ts, mft_cols, file_findings)
            if len(batch) >= BATCH:
                self._flush_lines(con, batch)
                st["lines"] += len(batch)
                batch = []
                if self._cancel:
                    break
        if batch:
            self._flush_lines(con, batch)
            st["lines"] += len(batch)

        if self.fts:
            con.execute("INSERT INTO lines_fts(rowid, text) SELECT id, text FROM lines WHERE file_id=?", (fid,))
        for (etype, val), (meta, hits, first, lns) in ents.items():
            con.execute("INSERT INTO entities(type, value, meta) VALUES(?,?,?) "
                        "ON CONFLICT(type, value) DO NOTHING", (etype, val, meta))
            eid = con.execute("SELECT id FROM entities WHERE type=? AND value=?", (etype, val)).fetchone()[0]
            con.execute("INSERT INTO entity_files(entity_id, file_id, hits, first_line, lines) VALUES(?,?,?,?,?)",
                        (eid, fid, hits, first, ",".join(map(str, lns))))
        con.executemany("INSERT INTO findings(rule, severity, category, scope, file_id, line_no, ts, ts_end, snippet, detail) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?)", findings)
        self._insert_decoded(con, fid, decoded_rows)

        # --- continuity verdicts
        integrity = {}
        if continuity and ts_count >= 50 and min_e is not None:
            span = max_e - min_e
            avg = span / ts_count if ts_count else 0
            integrity["cadence_seconds"] = round(avg, 1)
            if n_back and n_back / ts_count < 0.02:
                top = sorted(backs, reverse=True)[:10]
                integrity["backwards"] = [{"seconds": d, "line": ln, "from": a, "to": b} for d, _pl, ln, a, b in top]
                for d, _pl, ln, a, b in top:
                    file_findings.append(("log_backwards", ln, b, None,
                                          f"line {ln} is dated {b}, {_dur(d)} earlier than the entries before it "
                                          f"(latest so far {a}): inserted or out of place", None))
            elif n_back:
                integrity["interleaved"] = True  # many backward steps: merged sources, not tampering evidence
            thr = max(1800, 25 * avg)
            big = sorted((g for g in gaps if g[0] >= thr), reverse=True)[:15]
            if big:
                integrity["gaps"] = [{"seconds": d, "line": ln, "from": a, "to": b} for d, _pl, ln, a, b in big]
                for d, _pl, ln, a, b in big:
                    sev_note = "" if avg < 600 else " (log is sparse; judge with care)"
                    file_findings.append(("log_gap", ln, a, b,
                                          f"no entries for {_dur(d)}, from {a} to {b} (usual spacing {_dur(avg)}){sev_note}",
                                          None))
        for kind_, ids in rec_ids.items():
            gl = seq_gaps(ids)
            if gl:
                label = "EventRecordID" if kind_ == "event" else "audit serial"
                integrity.setdefault("record_gaps", []).extend(
                    {"kind": label, "after": a, "before": b, "missing": b - a - 1} for a, b in gl)
                for a, b in gl:
                    la, ta = ids[a]
                    lb, tb = ids[b]
                    extra = " (auditd can also skip serials for filtered events)" if kind_ == "audit" else ""
                    file_findings.append(("record_gap", lb, ta, tb,
                                          f"{label} {a} is followed by {b}: {b - a - 1:,} records missing"
                                          f"{f', between {ta} and {tb}' if ta and tb else ''}{extra}", None))
        return {"n": n, "first_ts": first_ts, "last_ts": last_ts, "ts_count": ts_count,
                "watch": {k: tuple(v) for k, v in watch_res.items()}, "findings": file_findings,
                "integrity": integrity}

    @staticmethod
    def _mft_row(line, n, ts, cols, out):
        try:
            row = next(csv.reader([line]))
        except (csv.Error, StopIteration):
            return
        g = lambda k: row[cols[k]] if cols.get(k) is not None and cols[k] < len(row) else ""
        path = (g("parent").rstrip("\\") + "\\" + g("name")).strip("\\")
        when = az.parse_timestamp(g("m10")) or ts
        if g("si").strip().lower() == "true":
            out.append(("mft_si_fn", n, az.parse_timestamp(g("c30")) or when, None,
                        f"{path}: $SI created {g('c10')} but $FN created {g('c30')}", None))
        elif g("usec").strip().lower() == "true":
            out.append(("mft_usec_zero", n, when, None, f"{path}: modified {g('m10')} with zero sub-seconds", None))

    @staticmethod
    def _flush_lines(con, batch):
        con.executemany("INSERT INTO lines(file_id, line_no, ts, text) VALUES(?,?,?,?)", batch)

    # whole case -------------------------------------------------------------
    def _analyze_case(self, con):
        for r in con.execute("SELECT id FROM files WHERE rel LIKE '[crumbs]/%'").fetchall():
            self._purge(con, r[0])     # generated files are rebuilt every run
        con.execute("DELETE FROM findings WHERE scope='case'")
        con.execute("DELETE FROM facts WHERE scope='case' AND kind='tool_present'")
        files = [dict(r) for r in con.execute(
            "SELECT id, rel, name, size, mtime_ns, ctime_ns, atime_ns, birth_ns, inode, uid, gid, sha256, md5, magic, "
            "mode, entropy, first_ts, last_ts, status FROM files WHERE rel NOT LIKE '[crumbs]/%' AND rel NOT LIKE '%!/%'")]
        out = []  # (rule, file_id, line_no, ts, ts_end, snippet, detail)
        now = time.time()
        notes = []
        n = len(files)

        # filesystem timestamps
        with_ns = [f for f in files if f["mtime_ns"]]
        nonzero = sum(1 for f in with_ns if f["mtime_ns"] % 1_000_000_000)
        precise_fs = len(with_ns) >= 5 and nonzero / len(with_ns) >= 0.8
        system_root = fsweep.system_prefix(files) is not None
        if system_root:
            precise_fs = False   # dpkg writes whole-second times: the Debian-aware sweep handles this instead
        for f in with_ns:
            m = f["mtime_ns"] / 1e9
            if m > now + 86400:
                out.append(("future_mtime", f["id"], None, ns_ts(f["mtime_ns"]), None,
                            f"{f['rel']} modified {ns_ts(f['mtime_ns'])} UTC, which is in the future", None))
            elif precise_fs and f["mtime_ns"] % 1_000_000_000 == 0:
                ch = f["ctime_ns"]
                if ch and ch / 1e9 - m > 86400:
                    out.append(("backdated_mtime", f["id"], None, ns_ts(ch), None,
                                f"{f['rel']}: modified time {ns_ts(f['mtime_ns'])} is a whole second, but the inode "
                                f"changed {ns_ts(ch)} ({_dur(ch / 1e9 - m)} later): modified time was likely set back then",
                                None))
                else:
                    out.append(("zero_ns_mtime", f["id"], None, ns_ts(f["mtime_ns"]), None,
                                f"{f['rel']} modified {ns_ts(f['mtime_ns'])} with exactly zero sub-seconds", None))

        # bursts of modification / metadata change
        def bursts(key, rule, label):
            pts = sorted(((f[key] / 1e9, f) for f in files if f[key]), key=lambda x: x[0])
            if len(pts) < 10:
                return None
            clusters, cur = [], [pts[0]]
            for p_ in pts[1:]:
                if p_[0] - cur[-1][0] <= 30:
                    cur.append(p_)
                else:
                    clusters.append(cur)
                    cur = [p_]
            clusters.append(cur)
            biggest = max(len(c) for c in clusters)
            if biggest >= 0.9 * len(pts):
                return f"{biggest} of {len(pts)} files {label} at nearly the same moment: these timestamps " \
                       f"probably come from copying or extracting the evidence, not from the original system."
            for c in clusters:
                if len(c) >= max(8, 0.05 * len(pts)):
                    fl = [x[1] for x in c]
                    hi = sum(1 for x in fl if (x["entropy"] or 0) > 7.2)
                    folders = sorted({x["rel"].rsplit("/", 1)[0] if "/" in x["rel"] else "." for x in fl})
                    extra = f"; {hi} now look random/encrypted" if hi else ""
                    out.append((rule, None, None, ns_ts(c[0][0] * 1e9), ns_ts(c[-1][0] * 1e9),
                                f"{len(c)} files {label} within {_dur(c[-1][0] - c[0][0])} in "
                                f"{', '.join(folders[:4])}{' …' if len(folders) > 4 else ''}{extra}",
                                json.dumps([{"id": x["id"], "rel": x["rel"]} for x in fl[:300]])))
            return None
        for key, rule, label in (("mtime_ns", "mass_modification", "modified"),
                                 ("ctime_ns", "metadata_burst", "had metadata changed")):
            note = bursts(key, rule, label)
            if note:
                notes.append(note)

        # folders changed after everything they still contain -> something left the folder
        children = {}
        for f in files:
            d = f["rel"].rsplit("/", 1)[0] if "/" in f["rel"] else "."
            t = max(x for x in (f["mtime_ns"], f["ctime_ns"], f["birth_ns"]) if x is not None) if f["mtime_ns"] else 0
            children[d] = max(children.get(d, 0), t)
        dirs = [dict(r) for r in con.execute("SELECT rel, mtime_ns, ctime_ns, birth_ns, entries FROM dirs")]
        for d in dirs:
            parent = d["rel"].rsplit("/", 1)[0] if "/" in d["rel"] else "."
            if d["rel"] != ".":
                t = max(x for x in (d["birth_ns"], d["ctime_ns"], d["mtime_ns"] if not d["entries"] else None, 0)
                        if x is not None)
                children[parent] = max(children.get(parent, 0), t)
        flagged = []
        for d in ([] if system_root else dirs):
            newest = children.get(d["rel"], 0)
            if d["mtime_ns"] and d["mtime_ns"] - newest > 2e9:
                flagged.append(d)
        if dirs and len(flagged) > 0.6 * len(dirs) and len(dirs) >= 5:
            notes.append("Most folders were modified after all of their contents: folder timestamps probably come "
                         "from copying the evidence, so folder-based deletion times are not reliable.")
        else:
            for d in flagged[:200]:
                newest = children.get(d["rel"], 0)
                what = "now empty" if not d["entries"] else f"{d['entries']} entries remain"
                out.append(("dir_changed_after_children", None, None, ns_ts(d["mtime_ns"]), None,
                            f"folder '{d['rel']}' last changed {ns_ts(d['mtime_ns'])} UTC, "
                            f"{_dur(d['mtime_ns'] / 1e9 - newest / 1e9) + ' after' if newest else 'with no'} "
                            f"its newest remaining item ({what})", None))

        # rotated log sequences
        groups = {}
        by_rel = {f["rel"]: f for f in files}
        for f in files:
            folder = f["rel"].rsplit("/", 1)[0] if "/" in f["rel"] else ""
            m = az.ROTATION_RX.match(f["name"])
            if m:
                groups.setdefault((folder, m.group("base")), {})[int(m.group("n"))] = f
        for (folder, base), members in groups.items():
            nums = set(members)
            cur_ = by_rel.get(f"{folder}/{base}" if folder else base)
            if cur_:
                members[0] = cur_
            missing = sorted(set(range(1, max(nums) + 1)) - nums)
            if missing and max(nums) >= 2:
                some = next(iter(members.values()))
                out.append(("rotation_missing", some["id"], None, None, None,
                            f"{folder + '/' if folder else ''}{base}: have {', '.join('.' + str(k) for k in sorted(nums))}, "
                            f"missing {', '.join('.' + str(k) for k in missing[:20])}", None))
            order = sorted(members)
            for newer, older in zip(order, order[1:]):
                a, b = members[older], members[newer]
                if a["last_ts"] and b["first_ts"]:
                    ea, eb = az.ts_to_epoch(a["last_ts"]), az.ts_to_epoch(b["first_ts"])
                    if ea and eb and eb - ea > 86400:
                        out.append(("rotation_gap", b["id"], 1, a["last_ts"], b["first_ts"],
                                    f"{a['name']} ends {a['last_ts']}, {b['name']} starts {b['first_ts']}: "
                                    f"{_dur(eb - ea)} with no log at all", None))

        # copies and diverging versions
        by_hash, by_name = {}, {}
        for f in files:
            if f["sha256"] and f["size"]:
                by_hash.setdefault(f["sha256"], []).append(f)
            if f["size"] and not az.ROTATION_RX.match(f["name"]):
                by_name.setdefault(f["name"], []).append(f)
        for h, fl in list(by_hash.items())[:5000]:
            names = {x["name"] for x in fl}
            if len(fl) > 1 and len(names) > 1:
                fl.sort(key=lambda x: x["mtime_ns"] or 0)
                out.append(("duplicate_content", fl[0]["id"], None, ns_ts(fl[0]["mtime_ns"]), ns_ts(fl[-1]["mtime_ns"]),
                            f"same content: {', '.join(x['rel'] for x in fl[:6])}{' …' if len(fl) > 6 else ''}",
                            json.dumps([{"id": x["id"], "rel": x["rel"]} for x in fl[:50]])))
        for name, fl in by_name.items():
            hashes = {x["sha256"] for x in fl if x["sha256"]}
            if 2 <= len(hashes) <= 10 and len(fl) <= 10:
                fl.sort(key=lambda x: x["mtime_ns"] or 0)
                out.append(("diverging_versions", fl[-1]["id"], None, ns_ts(fl[0]["mtime_ns"]), ns_ts(fl[-1]["mtime_ns"]),
                            f"{name}: {len(hashes)} different versions at {', '.join(x['rel'] for x in fl[:5])}",
                            json.dumps([{"id": x["id"], "rel": x["rel"]} for x in fl])))

        # whole-filesystem sweep: deleted files, backdated timestamps, orphaned owners (full dumps)
        if system_root:
            try:
                out.extend(fsweep.analyze(con, files, get_meta(con, "root") or ""))
            except Exception as e:
                import traceback
                notes.append(f"Filesystem sweep failed: {e}")
                self.state["errors"].append("fsweep: " + traceback.format_exc()[-800:])

        # Debian / Linux host correlations
        try:
            out.extend(linux.analyze_case(con, files))
        except Exception as e:  # never let one analysis break the index
            notes.append(f"Linux host analysis failed: {e}")

        # leftovers
        for f in files:
            if az.LEFTOVER_RX.search(f["name"]):
                out.append(("leftover_file", f["id"], None, ns_ts(f["mtime_ns"]), None,
                            f"{f['rel']} (last modified {ns_ts(f['mtime_ns'])} UTC)", None))

        rows = []
        for rule, fid, line_no, ts, ts_end, snippet, detail in out:
            ri = az.RULE_INFO[rule]
            rows.append((rule, ri["severity"], ri["category"], "case", fid, line_no, ts, ts_end, snippet[:600], detail))
        con.executemany("INSERT INTO findings(rule, severity, category, scope, file_id, line_no, ts, ts_end, snippet, detail) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?)", rows)
        # second stage: initial access, remote-control channels and internal control need the case findings above
        try:
            rows = []
            for rule, fid, line_no, ts, ts_end, snippet, detail in webaccess.analyze_case(con, files):
                ri = az.RULE_INFO[rule]
                rows.append((rule, ri["severity"], ri["category"], "case", fid, line_no, ts, ts_end, snippet[:600], detail))
            con.executemany("INSERT INTO findings(rule, severity, category, scope, file_id, line_no, ts, ts_end, snippet, detail) "
                            "VALUES(?,?,?,?,?,?,?,?,?,?)", rows)
        except Exception as e:
            notes.append(f"Web / remote-control analysis failed: {e}")
        try:
            rows = []
            for rule, fid, line_no, ts, ts_end, snippet, detail in toolhunt.finalize(con, files):
                ri = az.RULE_INFO[rule]
                rows.append((rule, ri["severity"], ri["category"], "case", fid, line_no, ts, ts_end, snippet[:600], detail))
            con.executemany("INSERT INTO findings(rule, severity, category, scope, file_id, line_no, ts, ts_end, snippet, detail) "
                            "VALUES(?,?,?,?,?,?,?,?,?,?)", rows)
        except Exception as e:
            notes.append(f"Tool inventory failed: {e}")
        set_meta(con, "fs_notes", json.dumps(notes))
        set_meta(con, "ctime_kind", "creation" if os.name == "nt" else "inode change")
