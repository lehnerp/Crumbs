"""
Readers for non-plain-text evidence and byte-level profiling of every file.
All stdlib; evidence files are only ever opened read-only.
"""
import gzip
import hashlib
import math
import os
import re
import sqlite3
import struct
import urllib.request
from collections import Counter

from analyzers import epoch_to_ts

CHUNK = 1 << 20
ENTROPY_SAMPLE = 4 << 20
TEXT_SAMPLE = 64 << 10
NUL_RUN = re.compile(rb"\x00{32,}")
NUL_LEAD = re.compile(rb"\x00+")
MAX_REGIONS = 200

MAGICS = [
    (0, b"ElfFile\x00", "evtx", "Windows event log (EVTX)"),
    (0, b"SQLite format 3\x00", "sqlite", "SQLite database"),
    (0, b"b0VIM ", "vimswap", "Vim swap file"),
    (0, b"MZ", "pe", "Windows executable (PE)"),
    (0, b"\x7fELF", "elf", "ELF executable"),
    (0, b"PK\x03\x04", "zip", "ZIP / Office document"),
    (0, b"\x1f\x8b", "gzip", "gzip"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip archive"),
    (0, b"Rar!", "rar", "RAR archive"),
    (0, b"%PDF", "pdf", "PDF"),
    (0, b"\x89PNG", "png", "PNG image"),
    (0, b"\xff\xd8\xff", "jpeg", "JPEG image"),
    (0, b"GIF8", "gif", "GIF image"),
    (0, b"regf", "registry", "Registry hive"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole", "OLE / legacy Office"),
    (0, b"BZh", "bzip2", "bzip2"),
    (0, b"\xfd7zXZ\x00", "xz", "xz"),
    (0, b"\xd4\xc3\xb2\xa1", "pcap", "pcap capture"),
    (0, b"\xa1\xb2\xc3\xd4", "pcap", "pcap capture"),
    (0, b"\x0a\x0d\x0d\x0a", "pcapng", "pcapng capture"),
    (0, b"\xca\xfe\xba\xbe", "macho", "Mach-O / Java class"),
    (0, b"\xcf\xfa\xed\xfe", "macho", "Mach-O executable"),
    (0, b"L\x00\x00\x00\x01\x14\x02\x00", "lnk", "Windows shortcut (LNK)"),
    (4, b"SCCA", "prefetch", "Windows Prefetch"),
    (0, b"MAM\x04", "prefetch", "Windows Prefetch (compressed)"),
    (0, b"FILE0", "mft", "NTFS $MFT"),
    (0, b"Salted__", "openssl", "OpenSSL-encrypted data"),
    (0, b"\x00\x00\x00\x18ftyp", "mp4", "MP4 video"),
    (0, b"\x00\x00\x00\x20ftyp", "mp4", "MP4 video"),
    (0, b"OggS", "ogg", "Ogg media"),
    (0, b"ID3", "mp3", "MP3 audio"),
    (0, b"TZif", "tzif", "Time zone data"),
    (0, b"LPKSHHRH", "journal", "systemd journal"),
    (0, b"UPX!", "upx", "UPX-packed program"),
]
# formats whose printable strings are worth indexing (compressed / media ones are noise)
STRINGS_OK = {None, "pe", "elf", "macho", "registry", "mft", "lnk", "prefetch", "ole", "pcap", "pcapng", "unknown", "journal", "upx"}
EXT_EXPECTS = {  # extension -> acceptable magic kinds; anything text-like expects no binary magic
    ".exe": {"pe"}, ".dll": {"pe"}, ".sys": {"pe"}, ".scr": {"pe"},
    ".zip": {"zip"}, ".docx": {"zip"}, ".xlsx": {"zip"}, ".pptx": {"zip"}, ".jar": {"zip"}, ".apk": {"zip"},
    ".pdf": {"pdf"}, ".png": {"png"}, ".jpg": {"jpeg"}, ".jpeg": {"jpeg"}, ".gif": {"gif"},
    ".gz": {"gzip"}, ".7z": {"7z"}, ".rar": {"rar"}, ".evtx": {"evtx"}, ".db": {"sqlite"}, ".sqlite": {"sqlite"},
    ".doc": {"ole"}, ".xls": {"ole"}, ".ppt": {"ole"}, ".msi": {"ole"}, ".lnk": {"lnk"}, ".pf": {"prefetch"},
}


def detect_magic(head):
    for off, sig, kind, label in MAGICS:
        if head[off:off + len(sig)] == sig:
            return kind, label
    return None, None


def filetime_to_ts(ft):
    if not ft:
        return None
    return epoch_to_ts((ft - 116444736000000000) / 1e7)


# --------------------------------------------------------------- profiler ---
try:
    import numpy as _np          # fast byte histogram for entropy (optional)
except Exception:
    _np = None


# ------------------------------------------------------- compressed streams ---
import bz2 as _bz2
import io as _io
import lzma as _lzma
import zlib as _zlib

COMPRESSION_MAGIC = ((b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"), (b"\xfd7zXZ\x00", "xz"))
MAX_DECODED = 8 * 1024 ** 3     # stop decoding a single stream after 8 GB (decompression bombs)


def compression_of(path):
    """'gzip', 'bzip2' or 'xz' when the file content is compressed (by its bytes, not its name)."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(6)
    except OSError:
        return None
    for magic, kind in COMPRESSION_MAGIC:
        if head.startswith(magic):
            return kind
    return None


class DecodedStream(_io.RawIOBase):
    """Read-only decompressed view of a gzip / bzip2 / xz file.

    Unlike gzip.open, a stream that is cut short (a rotated log truncated, partly overwritten or carved)
    is not an error: everything that decodes is returned and `truncated` is set. Concatenated members
    (gzip -c a >> b) are followed."""

    CH = 1 << 20

    def __init__(self, path, kind=None):
        self.fh = open(path, "rb")
        self.kind = kind or compression_of(path)
        if self.kind not in ("gzip", "bzip2", "xz"):
            self.fh.close()
            raise ValueError("not a compressed file")
        self.d = self._new()
        self.pending = b""          # compressed input not yet fed
        self.out, self.pos = b"", 0
        self.done = False
        self.truncated = False
        self.error = None
        self.members = 1
        self.decoded = 0
        self.trailing = 0           # bytes after the last complete member that are not another member

    def _new(self):
        if self.kind == "gzip":
            return _zlib.decompressobj(16 + _zlib.MAX_WBITS)
        if self.kind == "bzip2":
            return _bz2.BZ2Decompressor()
        return _lzma.LZMADecompressor()

    def readable(self):
        return True

    def readinto(self, b):
        while self.pos >= len(self.out) and not self.done:
            self._fill()
        n = min(len(b), len(self.out) - self.pos)
        b[:n] = self.out[self.pos:self.pos + n]
        self.pos += n
        return n

    def _fill(self):
        self.out, self.pos = b"", 0
        if self.decoded >= MAX_DECODED:
            self.done, self.truncated = True, True
            self.error = f"stopped after {MAX_DECODED // 1024 ** 3} GB of decompressed data"
            return
        if self.d is not None and self.kind != "gzip" and not self.d.needs_input and not self.d.eof:
            try:                                  # output still buffered inside bz2 / lzma
                self.out = self.d.decompress(b"", max_length=self.CH * 4)
            except (OSError, EOFError, _lzma.LZMAError, ValueError) as e:
                self.truncated, self.error, self.done = True, f"damaged compressed data: {e}", True
                return
            if self.d.eof:
                self.pending = self.d.unused_data + self.pending
                self.d = None
            self.decoded += len(self.out)
            return
        if not self.pending:
            self.pending = self.fh.read(self.CH)
            if not self.pending:
                if self.d is not None and not self.d.eof:
                    if self.kind == "gzip":
                        try:
                            self.out = self.d.flush()
                        except _zlib.error:
                            pass
                    self.truncated = True
                    self.error = self.error or "compressed data ends before the end of the stream"
                self.done = True
                self.decoded += len(self.out)
                return
        if self.d is None:                       # previous member complete: is this another one?
            if any(self.pending.startswith(m) for m, k in COMPRESSION_MAGIC if k == self.kind):
                self.d = self._new()
                self.members += 1
            else:
                if self.pending.strip(b"\x00"):
                    self.trailing += len(self.pending)
                self.pending = b""
                return
        try:
            if self.kind == "gzip":
                self.out = self.d.decompress(self.pending, self.CH * 4)
                self.pending = self.d.unconsumed_tail
            else:
                self.out = self.d.decompress(self.pending, max_length=self.CH * 4)
                self.pending = b""
        except (_zlib.error, OSError, EOFError, _lzma.LZMAError, ValueError) as e:
            self.truncated, self.error, self.done = True, f"damaged compressed data: {e}", True
            self.out = b""
            return
        if self.d.eof:
            self.pending = self.d.unused_data + self.pending
            self.d = None
        self.decoded += len(self.out)

    def close(self):
        try:
            self.fh.close()
        finally:
            super().close()


def open_decoded(path, kind=None):
    """Binary file object of the file's content, decompressed when it is gzip / bzip2 / xz."""
    kind = kind or compression_of(path)
    if kind:
        return _io.BufferedReader(DecodedStream(path, kind), buffer_size=1 << 20)
    return open(path, "rb")


def open_decoded_text(path, encoding, kind=None):
    kind = kind or compression_of(path)
    if kind:
        return _io.TextIOWrapper(open_decoded(path, kind), encoding=encoding or "utf-8", errors="replace", newline="")
    return open(path, "r", encoding=encoding or "utf-8", errors="replace", newline="")


def read_decoded(path, limit=None):
    with open_decoded(path) as fh:
        return fh.read(limit) if limit else fh.read()


# ------------------------------------------------------------------ archives ---
import calendar as _cal
import json as _json
import shutil as _shutil
import tarfile as _tarfile
import zipfile as _zipfile

ARCHIVE_MAX_MEMBERS = 20_000
ARCHIVE_MAX_TOTAL = 4 * 1024 ** 3


def archive_kind(path, name):
    """'tar' (plain, gzip, bzip2 or xz compressed) or 'zip', judged by content. Zip only for *.zip, so office
    documents and Java/Android packages are left alone."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
        if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
            return "zip" if name.lower().endswith(".zip") else None
        with open_decoded(path) as fh:
            h = fh.read(512)
        if len(h) >= 262 and h[257:262] == b"ustar":
            return "tar"
    except (OSError, EOFError, ValueError):
        pass
    return None


def _store_name(n, inner):
    base = inner.replace("\\", "/").rsplit("/", 1)[-1]
    base = "".join(c if (c.isalnum() or c in "._-") else "_" for c in base)[:60].rstrip(". ") or "member"
    return f"{n:06d}_{base}"


def _clean_inner(name):
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".", "..")]
    return "/".join(parts) or "(unnamed)"


def _zip_mtime(info):
    """UTC modified time: the Unix extended-timestamp field when present, otherwise the DOS time (no time zone)."""
    ex = info.extra
    i = 0
    while i + 4 <= len(ex):
        tag, size = int.from_bytes(ex[i:i + 2], "little"), int.from_bytes(ex[i + 2:i + 4], "little")
        body = ex[i + 4:i + 4 + size]
        if tag == 0x5455 and size >= 5 and body[0] & 1:
            return int.from_bytes(body[1:5], "little"), True
        i += 4 + size
    try:
        return _cal.timegm(info.date_time + (0, 0, 0)), False
    except (ValueError, OverflowError):
        return None, False


def expand_archive(path, kind, dest, max_member):
    """Extract regular members to `dest` (re-used while the archive is unchanged).
    Returns (members [(stored path, inner name)], summary)."""
    st = os.stat(path)
    manifest = os.path.join(dest, "manifest.json")
    try:
        m = _json.load(open(manifest, encoding="utf-8"))
        if m.get("size") == st.st_size and m.get("mtime_ns") == st.st_mtime_ns and m.get("v") == 1:
            if all(os.path.exists(os.path.join(dest, f)) for f, _i in m["members"]):
                return [(os.path.join(dest, f), i) for f, i in m["members"]], m["summary"]
    except (OSError, ValueError, KeyError, TypeError):
        pass
    _shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(dest, exist_ok=True)
    out, total = [], 0
    sm = {"kind": kind, "compression": compression_of(path) if kind == "tar" else None, "entries": 0,
          "extracted": 0, "too_big": 0, "not_files": 0, "encrypted": 0, "truncated": False, "error": None,
          "limit": None, "dos_times": False, "escaping": []}

    def write(inner, fobj, mtime, raw_name=""):
        nonlocal total
        rn = raw_name.replace("\\", "/")
        if (rn.startswith("/") or ".." in rn.split("/") or re.match(r"^[A-Za-z]:", rn)) and len(sm["escaping"]) < 50:
            sm["escaping"].append(raw_name[:200])
        stored = _store_name(len(out) + 1, inner)
        target = os.path.join(dest, stored)
        n = 0
        with open(target, "wb") as w:
            for c in iter(lambda: fobj.read(1 << 20), b""):
                w.write(c)
                n += len(c)
        if mtime is not None:
            try:
                os.utime(target, (mtime, mtime))
            except (OSError, OverflowError, ValueError):
                pass
        total += n
        out.append((stored, inner))
        sm["extracted"] += 1

    try:
        if kind == "tar":
            with open_decoded(path) as raw, _tarfile.open(fileobj=raw, mode="r|") as tf:
                for ti in tf:
                    sm["entries"] += 1
                    if sm["entries"] > ARCHIVE_MAX_MEMBERS or total > ARCHIVE_MAX_TOTAL:
                        sm["limit"] = f"stopped after {ARCHIVE_MAX_MEMBERS:,} entries / {ARCHIVE_MAX_TOTAL // 1024 ** 3} GB"
                        break
                    if not ti.isreg():
                        sm["not_files"] += 1
                        continue
                    if ti.size > max_member:
                        sm["too_big"] += 1
                        continue
                    fobj = tf.extractfile(ti)
                    if fobj is not None:
                        write(_clean_inner(ti.name), fobj, ti.mtime, ti.name)
                try:
                    sm["truncated"] = bool(getattr(raw.raw, "truncated", False))
                except AttributeError:
                    pass
        else:
            with _zipfile.ZipFile(path) as zf:
                for zi in zf.infolist():
                    sm["entries"] += 1
                    if sm["entries"] > ARCHIVE_MAX_MEMBERS or total > ARCHIVE_MAX_TOTAL:
                        sm["limit"] = f"stopped after {ARCHIVE_MAX_MEMBERS:,} entries / {ARCHIVE_MAX_TOTAL // 1024 ** 3} GB"
                        break
                    if zi.is_dir():
                        sm["not_files"] += 1
                        continue
                    if zi.flag_bits & 1:
                        sm["encrypted"] += 1
                        continue
                    if zi.file_size > max_member:
                        sm["too_big"] += 1
                        continue
                    mt, utc = _zip_mtime(zi)
                    sm["dos_times"] |= not utc
                    try:
                        with zf.open(zi) as fobj:
                            write(_clean_inner(zi.filename), fobj, mt, zi.filename)
                    except (_zipfile.BadZipFile, OSError, EOFError, NotImplementedError, ValueError) as e:
                        sm["error"] = f"{zi.filename}: {e}"
    except (_tarfile.TarError, _zipfile.BadZipFile, OSError, EOFError, ValueError) as e:
        sm["truncated"] = True
        sm["error"] = str(e)[:200]
    try:
        with open(manifest, "w", encoding="utf-8") as fh:
            _json.dump({"v": 1, "size": st.st_size, "mtime_ns": st.st_mtime_ns, "members": out, "summary": sm}, fh)
    except OSError:
        pass
    return [(os.path.join(dest, f), i) for f, i in out], sm


def archive_note(sm):
    k = "tar" + (f" ({sm['compression']})" if sm.get("compression") else "") if sm["kind"] == "tar" else "zip"
    bits = [f"{k} archive: {sm['extracted']:,} file(s) indexed as <archive>!/<path>"]
    if sm.get("too_big"):
        bits.append(f"{sm['too_big']} too large")
    if sm.get("encrypted"):
        bits.append(f"{sm['encrypted']} encrypted (not read)")
    if sm.get("not_files"):
        bits.append(f"{sm['not_files']} folders/links skipped")
    if sm.get("limit"):
        bits.append(sm["limit"])
    if sm.get("truncated"):
        bits.append("archive ends early or is damaged: " + (sm.get("error") or "truncated"))
    if sm.get("dos_times"):
        bits.append("zip times without a time zone (taken as UTC)")
    return "; ".join(bits)


def profile_file(path):
    """One pass over the file: sha256 (of the raw file), plus on the decoded stream (gz is
    decompressed): head bytes, NUL statistics and regions with line numbers, newline count,
    a NUL-free text sample, and Shannon entropy of the first few MB."""
    comp = compression_of(path)
    p = {"compression": comp, "truncated": False, "compress_error": None, "members": 1, "head": b"", "nul_bytes": 0, "nul_regions": [], "nul_region_count": 0, "newlines": 0,
         "text_sample": b"", "decoded_size": 0, "all_zero": True, "entropy": None, "error": None}
    counts = Counter()
    counted = 0
    pending = None  # [offset, length, line]

    def close(reg):
        p["nul_region_count"] += 1
        if len(p["nul_regions"]) < MAX_REGIONS:
            p["nul_regions"].append({"offset": reg[0], "length": reg[1], "line": reg[2]})

    def feed(chunk, base):
        nonlocal counted, pending
        if not p["head"]:
            p["head"] = chunk[:4096]
        nul = chunk.count(0)
        p["nul_bytes"] += nul
        if nul != len(chunk):
            p["all_zero"] = False
        if len(p["text_sample"]) < TEXT_SAMPLE:
            p["text_sample"] += (chunk.replace(b"\x00", b"") if nul else chunk)[:TEXT_SAMPLE - len(p["text_sample"])]
        if counted < ENTROPY_SAMPLE:
            part = chunk[:ENTROPY_SAMPLE - counted]
            if _np is not None:
                for b, c in enumerate(_np.bincount(_np.frombuffer(part, dtype=_np.uint8), minlength=256).tolist()):
                    if c:
                        counts[b] += c
            else:
                counts.update(part)
            counted += len(part)
        if nul:
            skip_to = 0
            if pending is not None:
                m = NUL_LEAD.match(chunk)
                if m:
                    pending[1] += m.end()
                    skip_to = m.end()
                if skip_to < len(chunk):
                    close(pending)
                    pending = None
            for m in NUL_RUN.finditer(chunk, skip_to):
                line = p["newlines"] + chunk.count(b"\n", 0, m.start()) + 1
                reg = [base + m.start(), m.end() - m.start(), line]
                if m.end() == len(chunk):
                    pending = reg
                else:
                    close(reg)
        elif pending is not None:
            close(pending)
            pending = None
        p["newlines"] += chunk.count(b"\n")

    sha = hashlib.sha256()
    md5 = hashlib.md5()
    try:
        if comp:
            with open(path, "rb") as fh:
                for c in iter(lambda: fh.read(CHUNK), b""):
                    sha.update(c)
                    md5.update(c)
            base = 0
            raw = DecodedStream(path, comp)
            with _io.BufferedReader(raw, buffer_size=1 << 20) as fh:
                for c in iter(lambda: fh.read(CHUNK), b""):
                    feed(c, base)
                    base += len(c)
                p.update(truncated=raw.truncated, compress_error=raw.error, members=raw.members)
            p["decoded_size"] = base
        else:
            base = 0
            with open(path, "rb") as fh:
                for c in iter(lambda: fh.read(CHUNK), b""):
                    sha.update(c)
                    md5.update(c)
                    feed(c, base)
                    base += len(c)
            p["decoded_size"] = base
    except (OSError, EOFError, gzip.BadGzipFile, ValueError) as e:
        p["error"] = str(e)
    if pending is not None:
        close(pending)
    if p["decoded_size"] == 0:
        p["all_zero"] = False
    p["sha256"] = sha.hexdigest()
    p["md5"] = md5.hexdigest()
    if counted:
        p["entropy"] = round(-sum((c / counted) * math.log2(c / counted) for c in counts.values()), 3)
    return p


def classify(p, name):
    """Decide how to read a file. Returns (kind, encoding, magic_kind, magic_label)."""
    head = p["head"]
    mkind, mlabel = detect_magic(head)
    if p["decoded_size"] == 0:
        return "empty", None, None, None
    if p["all_zero"]:
        return "zero", None, None, None
    if name.startswith("$I") and head[:8] in (b"\x01" + b"\x00" * 7, b"\x02" + b"\x00" * 7) and p["decoded_size"] < 8192:
        return "recycle", None, "recycle", "Recycle Bin index ($I)"
    if mkind in ("evtx", "sqlite", "vimswap"):
        return mkind, None, mkind, mlabel
    if head.startswith(b"\xef\xbb\xbf"):
        return "text", "utf-8-sig", None, None
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "text", "utf-16", None, None
    h = head[:4096]
    even, odd = h[0::2], h[1::2]
    if len(h) >= 16:
        if odd.count(0) > 0.4 * len(odd) and even.count(0) < 0.05 * len(even):
            return "text", "utf-16-le", None, None
        if even.count(0) > 0.4 * len(even) and odd.count(0) < 0.05 * len(odd):
            return "text", "utf-16-be", None, None
    if mkind:
        return "binary", None, mkind, mlabel
    s = p["text_sample"]
    if s:
        ctrl = sum(1 for b in s if b < 32 and b not in (9, 10, 12, 13, 27))
        if ctrl / len(s) < 0.05:
            try:
                s.decode("utf-8")
                enc = "utf-8"
            except UnicodeDecodeError as e:
                enc = "utf-8" if e.start >= len(s) - 4 else "latin-1"
            return "text", enc, None, None
    return "binary", None, "unknown", None


# -------------------------------------------------------------------- EVTX ---
UTF16_STR = re.compile(rb"(?:[\x20-\x7e]\x00){3,}")


class EvtxReader:
    """Minimal EVTX reader: record IDs, write times and the UTF-16 strings in each record.
    It does not decode binary XML (EventID numbers are not recovered), but the strings carry
    usernames, IPs, paths, command lines, provider and channel names."""

    def __init__(self, path, max_records=1_000_000):
        self.path = path
        self.max_records = max_records
        self.info = {"next_record_id": None, "dirty": False, "full": False, "chunks": 0, "records": 0}

    def lines(self):
        with open(self.path, "rb") as fh:
            header = fh.read(4096)
            if not header.startswith(b"ElfFile\x00"):
                return
            self.info["next_record_id"] = struct.unpack_from("<Q", header, 24)[0]
            flags = struct.unpack_from("<I", header, 120)[0]
            self.info["dirty"], self.info["full"] = bool(flags & 1), bool(flags & 2)
            while self.info["records"] < self.max_records:
                chunk = fh.read(65536)
                if len(chunk) < 512:
                    break
                if not chunk.startswith(b"ElfChnk\x00"):
                    continue
                self.info["chunks"] += 1
                pos = 512
                while pos + 24 <= len(chunk):
                    if chunk[pos:pos + 4] != b"\x2a\x2a\x00\x00":
                        break
                    size = struct.unpack_from("<I", chunk, pos + 4)[0]
                    if size < 24 or pos + size > len(chunk):
                        break
                    rid = struct.unpack_from("<Q", chunk, pos + 8)[0]
                    ts = filetime_to_ts(struct.unpack_from("<Q", chunk, pos + 16)[0])
                    seen, parts = set(), []
                    for m in UTF16_STR.finditer(chunk, pos + 24, pos + size):
                        s = m.group().decode("utf-16-le").strip()
                        if s and s not in seen:
                            seen.add(s)
                            parts.append(s)
                        if len(parts) >= 80:
                            break
                    self.info["records"] += 1
                    yield f"EventRecordID={rid} {ts or ''} | " + " | ".join(parts), ts
                    pos += size


# ----------------------------------------------------- small binary artifacts ---
def parse_recycle_i(data):
    """Windows Recycle Bin $I file -> original path, size and deletion time."""
    ver, size, ft = struct.unpack_from("<QQQ", data, 0)
    if ver == 1:
        path = data[24:24 + 520].decode("utf-16-le", "replace").split("\x00")[0]
    else:
        n = struct.unpack_from("<I", data, 24)[0]
        path = data[28:28 + 2 * n].decode("utf-16-le", "replace").rstrip("\x00")
    return {"path": path, "size": size, "deleted": filetime_to_ts(ft)}


def parse_vim_swap(data):
    """Vim swap file header -> editing user, host, pid, file being edited and its mtime."""
    cstr = lambda b: b.split(b"\x00")[0].decode("utf-8", "replace")
    return {
        "version": cstr(data[2:12]),
        "mtime": epoch_to_ts(int.from_bytes(data[16:20], "little")),
        "pid": int.from_bytes(data[24:28], "little"),
        "user": cstr(data[28:68]),
        "host": cstr(data[68:108]),
        "file": cstr(data[108:1008]),
    }


# ------------------------------------------------------------------ SQLite ---
_TIMECOL = re.compile(r"(?i)time|date|_at$|created|modified|visit|expires|when|last_|first_")


def guess_time(v):
    """Convert common integer/float timestamp encodings to 'YYYY-MM-DD HH:MM:SS'."""
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    if 1e9 <= v < 4.1e9:
        return epoch_to_ts(v)                      # unix seconds
    if 1e12 <= v < 4.1e12:
        return epoch_to_ts(v / 1e3)                # unix milliseconds
    if 1e15 <= v < 4.1e15:
        return epoch_to_ts(v / 1e6)                # unix microseconds (Firefox PRTime)
    if 1.1e16 <= v < 1.4e16:
        return epoch_to_ts(v / 1e6 - 11644473600)  # WebKit/Chrome microseconds since 1601
    if 1.1e17 <= v < 1.4e17:
        return epoch_to_ts(v / 1e7 - 11644473600)  # Windows FILETIME
    if 3e8 <= v < 1e9:
        return epoch_to_ts(v + 978307200)          # Apple absolute time (since 2001)
    return None


def sqlite_lines(path, max_lines=200_000):
    """Dump every table of a SQLite file (read-only, immutable) as one line per row."""
    uri = "file:" + urllib.request.pathname2url(os.path.abspath(path)) + "?mode=ro&immutable=1"
    con = sqlite3.connect(uri, uri=True)
    try:
        n = 0
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for t in tables:
            try:
                cur = con.execute('SELECT * FROM "%s"' % t.replace('"', '""'))
            except sqlite3.Error:
                continue
            cols = [d[0] for d in cur.description]
            timecols = {i for i, c in enumerate(cols) if _TIMECOL.search(c)}
            for row in cur:
                parts = []
                for i, v in enumerate(row):
                    if v is None or v == "":
                        continue
                    if isinstance(v, bytes):
                        v = f"<{len(v)} bytes>"
                    elif i in timecols and isinstance(v, (int, float)):
                        g = guess_time(v)
                        v = f"{v} ({g} UTC)" if g else v
                    parts.append(f"{cols[i]}={str(v)[:300]}")
                yield f"[{t}] " + " | ".join(parts)
                n += 1
                if n >= max_lines:
                    return
    finally:
        con.close()


# ------------------------------------------------------------ binary strings ---
ASCII_STR = re.compile(rb"[\x20-\x7e]{6,}")
UTF16_STR6 = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")


def binary_strings(path, max_lines=200_000):
    """Printable ASCII and UTF-16 strings with their byte offsets (like `strings -t x`)."""
    n = 0
    base = 0
    with open_decoded(path) as fh:
        for chunk in iter(lambda: fh.read(4 * CHUNK), b""):
            items = [(base + m.start(), m.group().decode("ascii")) for m in ASCII_STR.finditer(chunk)]
            items += [(base + m.start(), m.group().decode("utf-16-le")) for m in UTF16_STR6.finditer(chunk)]
            items.sort()
            for off, s in items:
                yield f"@{off:#010x} {s[:1000]}"
                n += 1
                if n >= max_lines:
                    return
            base += len(chunk)
