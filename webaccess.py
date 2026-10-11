"""
Web server compromise and remote control.

Per access log (Apache / nginx combined or common format) Crumbs keeps, per client and per script
URL, what is needed to answer:

  * How did they get in?  Exploit families (Log4Shell, Shellshock, LFI/RFI, RCE parameters, SSTI,
    XXE, known exploit paths, abused upload endpoints), the web shell's first request, the upload
    that most likely planted it (a POST shortly before the shell's file time / first use).
  * How did they keep control?  Web-shell use over days, periodic polling (beaconing),
    HTTP tunnels through a script (reGeorg / Neo-reGeorg / suo5 style: a flood of POSTs),
    and the same channels used from inside the network after the compromise began.

Beacon detection (`beacon`) is shared with firewall connection series and DNS queries.
"""
import ipaddress
from array import array
import json
import math
import re
from collections import Counter
from statistics import median, pstdev
from urllib.parse import unquote

import analyzers as az

R_ACCESS = re.compile(
    r'^(?:\S+:\d+ )?(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+)(?: (HTTP/[\d.]+))?" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?')
SCRIPT_EXT = re.compile(r"\.(?:php\d?|phtml|phar|jsp|jspx|asp|aspx|ashx|cgi|pl|py|sh|cfm)$", re.I)
UPLOADISH = re.compile(r"(?i)/(?:uploads?|files?|images?|img|media|tmp|temp|cache|assets|attachments?|userfiles|wp-content/uploads)/")
UPLOAD_ENDPOINT = re.compile(r"(?i)(upload|uploader|file-?manager|elfinder|connector|kcfinder|ckfinder|fckeditor|plupload|"
                             r"ajax-?upload|async-upload|media-new|import|attachment)[^/]*$")  # the handler's own name
FAMILIES = [
    ("log4shell", "high", re.compile(r"\$\{(?:jndi|\$\{|lower:|upper:|env:|::-)", re.I)),
    ("shellshock", "high", re.compile(r"\(\)\s*\{\s*:?\s*;?\s*\}\s*;")),
    ("rce", "high", re.compile(r"(?:[;|`]|\$\(|%0a|\|\|)\s*(?:id|whoami|uname|cat\s|wget|curl|bash|sh\s|nc\s|python|perl|php\s|chmod|echo\s)|"
                               r"[?&](?:cmd|exec|command|c|x|run|shell)=[^&]*(?:whoami|\bid\b|uname|wget|curl|bash|/bin/sh|cat\s)", re.I)),
    ("lfi", "medium", re.compile(r"\.\./\.\./|/etc/passwd|/proc/self/environ|php://(?:filter|input)|file://|expect://|data://text", re.I)),
    ("rfi", "high", re.compile(r"=(?:https?|ftp)://[^&\s]+\.(?:txt|php|sh|jpg)\?*", re.I)),
    ("sqli", "medium", re.compile(r"union(?:\s|\+)+(?:all(?:\s|\+)+)?select|'(?:\s|\+)*or(?:\s|\+)*'?1'?=|sleep\(\d+\)|benchmark\(|information_schema", re.I)),
    ("ssti", "high", re.compile(r"\{\{[^}]*(?:config|self|__class__|request|7\*7)[^}]*\}\}|\$\{\d+\*\d+\}|#\{\d+\*\d+\}", re.I)),
    ("xxe", "high", re.compile(r"<!ENTITY|SYSTEM\s+[\"']file:", re.I)),
    ("known_exploit", "high", re.compile(
        r"vendor/phpunit/.*eval-stdin\.php|wp-file-manager/lib/php/connector|invokefunction|/cgi-bin/(?:\.%2e|%2e%2e)|"
        r"/actuator/(?:env|gateway|jolokia)|/solr/admin/cores|/_ignition/execute-solution|/api/jsonws/invoke|"
        r"class\.module\.classLoader|/console/css/%252e|/jmx-console|/invoker/JMXInvokerServlet|/HNAP1|/boaform|"
        r"/wp-admin/admin-ajax\.php\?action=(?:revslider_show_image|duplicator_download)|/xmlrpc\.php\?rsd|"
        r"/druid/indexer|/mgmt/tm/util/bash|/remote/fgt_lang|/dana-na/|/vpn/\.\./vpns|/owa/auth/x\.js|/autodiscover/autodiscover\.json", re.I)),
    ("probe", "low", re.compile(r"/\.env$|/\.git/(?:config|HEAD)|/\.aws/|/\.ssh/|/wp-config\.php\.(?:bak|old|save)|/server-status|/phpinfo\.php|/\.DS_Store", re.I)),
]
SCANNER_UA = re.compile(r"(?i)sqlmap|nikto|nuclei|zgrab|masscan|wpscan|gobuster|dirbuster|feroxbuster|ffuf|wfuzz|acunetix|nessus|openvas|"
                        r"nmap scripting|jaeles|httpx|whatweb")
SCRIPTED_UA = re.compile(r"(?i)^(?:curl|wget|python-requests|python-urllib|go-http-client|libwww-perl|java/|okhttp|axios|php/)|^-$")
REGEORG = re.compile(r"(?i)[?&]cmd=(?:connect|forward|read|disconnect|disconn)\b|[?&]target=\d{1,3}(?:\.\d{1,3}){3}&port=\d+")

MAX_KEYS = 300000        # client + script pairs counted
MAX_TIMES = 6000         # timestamps per pair
TIME_BUDGET = 6_000_000  # timestamps kept in total (compact int arrays)


def _private(ip):
    """Inside the network (RFC 1918 etc.), but not the server talking to itself."""
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private and not a.is_loopback
    except ValueError:
        return False


class WebLog:
    def __init__(self, rel):
        self.rel = rel
        self.parsed = 0
        self.clients = {}
        self.scripts = {}     # (ip, path) -> dict
        self.paths = {}       # path -> first use
        self.uploads = []
        self.finds = []       # (rule, line_no, ts, snippet)
        self.fam_count = Counter()
        self.fam_agg = {}     # (ip, family) -> aggregate
        self.reg_agg = {}     # (ip, path) -> reGeorg-style requests
        self.path_ips = {}    # path -> set of client IPs (capped)
        self.time_used = 0

    def feed(self, n, line, ts):
        m = R_ACCESS.match(line)
        if not m:
            return
        ip, user, _t, method, url, _proto, status, size, ref, ua = m.groups()
        self.parsed += 1
        status = int(status)
        size = int(size) if size and size.isdigit() else 0
        path, _, query = url.partition("?")
        dec = unquote(unquote(url))
        e = az.ts_to_epoch(ts) if ts else None
        c = self.clients.get(ip)
        if c is None:
            if len(self.clients) > 200000:
                return
            c = self.clients[ip] = {"n": 0, "first": ts, "last": ts, "status": Counter(), "methods": Counter(), "fam": Counter(),
                                    "ua": Counter(), "n404": 0, "first_line": n, "exploit_ok": [], "posts": 0, "scripted": 0, "scanner": 0}
        c["n"] += 1
        c["last"] = ts or c["last"]
        c["status"][status // 100] += 1
        c["methods"][method] += 1
        if status == 404:
            c["n404"] += 1
        if len(c["ua"]) < 6 or ua in c["ua"]:
            c["ua"][ua or "-"] += 1
        if method == "POST":
            c["posts"] += 1
        if ua and SCANNER_UA.search(ua):
            c["scanner"] += 1
        if SCRIPTED_UA.search(ua or "-"):
            c["scripted"] += 1
        for fam, sev, rx in FAMILIES:
            if rx.search(dec) or (fam in ("log4shell", "shellshock") and rx.search(unquote(ua or "") + " " + unquote(ref or ""))):
                c["fam"][fam] += 1
                self.fam_count[fam] += 1
                if 200 <= status < 400 and fam != "probe" and len(c["exploit_ok"]) < 20:
                    c["exploit_ok"].append({"family": fam, "ts": ts, "line": n, "status": status, "url": url[:200], "method": method})
                if fam in ("log4shell", "shellshock", "known_exploit", "ssti", "xxe", "rfi", "rce", "lfi"):
                    a = self.fam_agg.get((ip, fam))
                    if a is None:
                        a = self.fam_agg[(ip, fam)] = {"n": 0, "line": n, "first": ts, "last": ts, "status": Counter(), "url": f"{method} {url[:200]}"}
                    a["n"] += 1
                    a["last"] = ts or a["last"]
                    a["status"][status] += 1
                break
        if REGEORG.search(url):
            a = self.reg_agg.get((ip, path))
            if a is None:
                a = self.reg_agg[(ip, path)] = {"n": 0, "line": n, "first": ts, "last": ts, "cmds": Counter()}
            a["n"] += 1
            a["last"] = ts or a["last"]
            m2 = re.search(r"cmd=(\w+)", url)
            a["cmds"][m2.group(1) if m2 else "?"] += 1
        script = bool(SCRIPT_EXT.search(path))
        if method == "POST" and (UPLOAD_ENDPOINT.search(path)) and 200 <= status < 400 and len(self.uploads) < 2000:
            self.uploads.append({"ip": ip, "ts": ts, "line": n, "path": path, "status": status, "size": size})
        if script or method == "POST" or UPLOADISH.search(path):
            ips = self.path_ips.get(path)
            if ips is None:
                ips = self.path_ips[path] = set()
            if len(ips) < 50:
                ips.add(ip)
            key = (ip, path)
            s = self.scripts.get(key)
            if s is None:
                if len(self.scripts) >= MAX_KEYS:
                    return
                s = self.scripts[key] = {"n": 0, "posts": 0, "first": ts, "first_line": n, "last": ts, "status": Counter(),
                                         "times": array("i"), "sizes": array("i"), "params": Counter(), "regeorg": 0}
            s["n"] += 1
            s["last"] = ts or s["last"]
            s["status"][status] += 1
            if method == "POST":
                s["posts"] += 1
            if e is not None and len(s["times"]) < MAX_TIMES and self.time_used < TIME_BUDGET:
                s["times"].append(int(e))
                self.time_used += 1
            if len(s["sizes"]) < 2000:
                s["sizes"].append(min(size, 2**31 - 1))
            for k in re.findall(r"(?:^|&)([\w-]{1,20})=", query)[:4]:
                s["params"][k] += 1
            if REGEORG.search(url):
                s["regeorg"] += 1
            p = self.paths.get(path)
            if p is None and len(self.paths) < MAX_KEYS:
                self.paths[path] = {"ts": ts, "ip": ip, "line": n, "status": status, "method": method}

    def facts(self):
        out = []
        if not self.parsed:
            return out
        # clients: keep the interesting ones (attack families, POST-heavy, scanners, or top talkers)
        def interest(c):
            return sum(c["fam"].values()) * 10 + c["posts"] + c["n404"] // 5 + c["scanner"] * 5 + (c["n"] // 100)
        top = sorted(self.clients.items(), key=lambda kv: -interest(kv[1]))[:3000]
        for ip, c in top:
            out.append(("web_client", c["first_line"], c["first"], ip, {
                "n": c["n"], "first": c["first"], "last": c["last"], "status": dict(c["status"]), "methods": dict(c["methods"]),
                "fam": dict(c["fam"]), "ua": c["ua"].most_common(4), "n404": c["n404"], "posts": c["posts"],
                "scanner": c["scanner"], "scripted": c["scripted"], "exploit_ok": c["exploit_ok"], "file": self.rel}))
        def keep(kv):
            (ip, path), s = kv
            few = len(self.path_ips.get(path, ())) <= 5        # a web shell has a handful of users; index.php has thousands
            return few or UPLOADISH.search(path) or s["regeorg"] or s["posts"] >= 0.5 * s["n"] and s["n"] >= 20
        chosen = sorted((kv for kv in self.scripts.items() if keep(kv)), key=lambda kv: -kv[1]["n"])[:3000]
        for (ip, path), s in chosen:
            out.append(("web_script", s["first_line"], s["first"], path, {
                "ip": ip, "n": s["n"], "posts": s["posts"], "first": s["first"], "last": s["last"], "status": dict(s["status"]),
                "times": list(s["times"]) if s["n"] >= 6 else [], "size_median": int(median(s["sizes"])) if s["sizes"] else 0,
                "params": s["params"].most_common(5), "regeorg": s["regeorg"], "users": len(self.path_ips.get(path, ())), "file": self.rel}))
        for (ip, fam), a in sorted(self.fam_agg.items(), key=lambda kv: kv[1]["first"] or ""):
            st = ", ".join(f"{k} ×{v}" for k, v in a["status"].most_common(3))
            self.finds.append(("web_exploit", a["line"], a["first"],
                               f"{fam} from {ip}: {a['n']} request(s) {a['first']} → {a['last']} (status {st}), e.g. {a['url']}"))
        for (ip, path), a in self.reg_agg.items():
            self.finds.append(("http_tunnel_request", a["line"], a["first"],
                               f"{ip} → {path}: {a['n']:,} tunnel requests ({', '.join(f'{k} ×{v}' for k, v in a['cmds'].most_common(4))}) "
                               f"{a['first']} → {a['last']}"))
        for path, p in self.paths.items():
            if SCRIPT_EXT.search(path) or UPLOADISH.search(path):
                out.append(("web_path_first", p["line"], p["ts"], path, dict(p, file=self.rel)))
        for u in self.uploads[:2000]:
            out.append(("web_upload", u["line"], u["ts"], u["path"], dict(u, file=self.rel)))
        return out


# ------------------------------------------------------------- beacons ---
def beacon(times, min_n=8):
    """Is this series of epoch seconds a regular poll? Returns {interval, jitter, n, ...} or None.
    Bursty use (a person clicking) has gaps of every size; an implant or cron poll has one dominant gap."""
    t = sorted(set(int(x) for x in times))
    if len(t) < min_n:
        return None
    d = [b - a for a, b in zip(t, t[1:]) if b - a >= 5]   # gaps under 5 s are bursts within one poll
    if len(d) < min_n - 1:
        return None
    med = median(d)
    if med < 20:
        return None
    near = sum(1 for x in d if abs(x - med) <= 0.2 * med)
    trimmed = sorted(d)[len(d) // 10: len(d) - len(d) // 10] or d
    mean = sum(trimmed) / len(trimmed)
    cv = pstdev(trimmed) / mean if mean else 9
    share = near / len(d)
    if share < 0.6 and cv > 0.3:
        return None
    return {"interval": int(med), "jitter": round(cv * 100), "share": round(share * 100), "n": len(t),
            "first": az.epoch_to_ts(t[0]), "last": az.epoch_to_ts(t[-1]), "span_h": round((t[-1] - t[0]) / 3600, 1)}


def human_interval(sec):
    return f"{sec} s" if sec < 120 else f"{sec / 60:.0f} min" if sec < 7200 else f"{sec / 3600:.1f} h"


def peak_per_minute(times):
    c = Counter(int(x) // 60 for x in times)
    return max(c.values()) if c else 0


# ------------------------------------------------------- dns tunnels ---
def _entropy(s):
    if not s:
        return 0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def dns_tunnel_check(qnames):
    """qnames: iterable of query names. Returns list of suspicious base domains with stats."""
    by = {}
    for q in qnames:
        q = q.strip(".").lower()
        parts = q.split(".")
        if len(parts) < 3:
            continue
        base = ".".join(parts[-2:])
        sub = ".".join(parts[:-2])
        b = by.setdefault(base, {"subs": set(), "n": 0, "lens": [], "ent": []})
        b["n"] += 1
        if len(b["subs"]) < 5000:
            b["subs"].add(sub)
            lab = max(parts[:-2], key=len)
            b["lens"].append(len(lab))
            b["ent"].append(_entropy(lab))
    out = []
    for base, b in by.items():
        u = len(b["subs"])
        if u < 30:
            continue
        avg = sum(b["lens"]) / len(b["lens"])
        ent = sum(b["ent"]) / len(b["ent"])
        if avg >= 20 or (avg >= 12 and ent >= 3.6):
            out.append({"domain": base, "queries": b["n"], "unique": u, "avg_label": round(avg, 1), "entropy": round(ent, 2),
                        "examples": sorted(b["subs"], key=len, reverse=True)[:3]})
    return out


# ------------------------------------------------------- case analysis ---
WEB_RULES = {
    "web_exploit": ("high", "attack", "Web exploit attempt (known exploit family)"),
    "http_tunnel_request": ("high", "c2", "HTTP tunnel request (reGeorg-style connect/read/forward)"),
    "webshell_first_use": ("high", "webshell", "Web shell: first use and who used it"),
    "initial_access": ("high", "access", "Most likely way in (initial access)"),
    "beaconing": ("high", "c2", "Regular polling (beaconing) to or from a control channel"),
    "http_tunnel": ("high", "c2", "HTTP tunnel through a script (flood of POSTs)"),
    "long_control": ("high", "c2", "Remote control over days through the same channel"),
    "internal_control": ("high", "lateral", "Attacker channel used from inside the network"),
    "internal_new_source": ("medium", "lateral", "Internal address first seen after the compromise began"),
    "dns_tunnel": ("high", "c2", "DNS tunnelling (many long random subdomains)"),
    "icmp_tunnel": ("high", "c2", "ICMP tunnelling (large echo payloads)"),
    "tunnel_installed": ("high", "c2", "Tunnel / VPN / Tor configuration on the host"),
    "exploit_succeeded": ("high", "attack", "Exploit request that the server answered successfully"),
}


def _facts(con, kind):
    for r in con.execute("SELECT file_id, line_no, ts, subject, data FROM facts WHERE kind=?", (kind,)):
        d = json.loads(r["data"])
        d.update(_file=r["file_id"], _line=r["line_no"], _ts=r["ts"], _subject=r["subject"])
        yield d


def analyze_case(con, files):
    out = []
    con.execute("DELETE FROM facts WHERE scope='case' AND kind IN ('initial_access','channel')")
    channels, hyps = [], []

    def channel(**kw):
        channels.append(kw)

    scripts = list(_facts(con, "web_script"))
    firsts = {}
    for p in _facts(con, "web_path_first"):
        cur = firsts.get(p["_subject"])
        if cur is None or (p["ts"] or "9") < (cur["ts"] or "9"):
            firsts[p["_subject"]] = p
    uploads = sorted(_facts(con, "web_upload"), key=lambda u: u["ts"] or "")
    clients = list(_facts(con, "web_client"))

    # --- web shells: files flagged as shells, mapped to their URL
    shell_files = {}
    for r in con.execute("SELECT DISTINCT f.id, f.rel, f.mtime_ns FROM findings fi JOIN files f ON f.id = fi.file_id "
                         "WHERE fi.category = 'webshell' OR fi.rule IN ('webshell','webshell_code','mail_loop')"):
        if SCRIPT_EXT.search(r["rel"]):
            shell_files[r["rel"]] = r
    for f in files:
        if SCRIPT_EXT.search(f["rel"]) and UPLOADISH.search("/" + f["rel"]) and f["rel"] not in shell_files:
            shell_files[f["rel"]] = {"id": f["id"], "rel": f["rel"], "mtime_ns": f["mtime_ns"]}
    by_path = {}
    for s in scripts:
        by_path.setdefault(s["_subject"], []).append(s)
    shell_urls = {}
    for rel, f in shell_files.items():
        for path in by_path:
            if len(path) > 4 and ("/" + rel).endswith(path):
                shell_urls[path] = f
    compromise_start = None
    for path, f in shell_urls.items():
        uses = sorted(by_path[path], key=lambda s: s["first"] or "")
        first = firsts.get(path) or {"ts": uses[0]["first"], "ip": uses[0]["ip"], "line": uses[0]["_line"], "file": uses[0]["file"]}
        total = sum(s["n"] for s in uses)
        ips = Counter()
        for s in uses:
            ips[s["ip"]] += s["n"]
        mt = az.epoch_to_ts(f["mtime_ns"] / 1e9) if f["mtime_ns"] else None
        last = max((s["last"] or "") for s in uses)
        fid = uses[0]["_file"]
        out.append(("webshell_first_use", fid, first.get("line"), first["ts"], last,
                    f"{path} (file {f['rel']}, last changed {mt} UTC) first requested {first['ts']} by {first['ip']}; "
                    f"{total:,} requests from {len(ips)} address(es): " + ", ".join(f"{ip} ×{n}" for ip, n in ips.most_common(4))
                    + f"; last {last}", None))
        if first["ts"] and (compromise_start is None or first["ts"] < compromise_start):
            compromise_start = first["ts"]
        # how did the shell arrive?
        e_first = az.ts_to_epoch(first["ts"]) if first["ts"] else None
        e_mt = f["mtime_ns"] / 1e9 if f["mtime_ns"] else None
        best = None
        for u in uploads:
            eu = az.ts_to_epoch(u["ts"]) if u["ts"] else None
            if eu is None or e_first is None or not (0 <= e_first - eu <= 86400):
                continue
            score = 1 + (2 if u["ip"] == first["ip"] else 0) + (3 if e_mt and abs(e_mt - eu) <= 120 else 0)
            if best is None or score > best[0] or (score == best[0] and eu > best[1]):
                best = (score, eu, u)
        if best:
            u = best[2]
            hyps.append({"ts": u["ts"], "kind": "Web upload planted a web shell", "confidence": "high" if best[0] >= 4 else "medium",
                         "ip": u["ip"], "file_id": u["_file"], "line": u["line"],
                         "evidence": [f"POST {u['path']} answered {u['status']} at {u['ts']} from {u['ip']}",
                                      f"{f['rel']} last changed {mt} UTC" + (" (within 2 min of the upload)" if e_mt and abs(e_mt - best[1]) <= 120 else ""),
                                      f"first request to {path} at {first['ts']} from {first['ip']}"]})
        else:
            hyps.append({"ts": first["ts"], "kind": "Web shell appeared (delivery not in the logs)", "confidence": "medium",
                         "ip": first["ip"], "file_id": fid, "line": first.get("line"),
                         "evidence": [f"first request to {path} at {first['ts']} from {first['ip']}",
                                      f"{f['rel']} last changed {mt} UTC; no upload request found in the 24 h before"]})
        for ip, n in ips.most_common(20):
            s_ip = [s for s in uses if s["ip"] == ip]
            a, z = min(s["first"] or "9" for s in s_ip), max(s["last"] or "" for s in s_ip)
            channel(kind="web shell", target=path, source=ip, internal=_private(ip), n=n, first=a, last=z,
                    file_id=s_ip[0]["_file"], line=s_ip[0]["_line"])

    # --- exploit requests that got a 2xx/3xx answer, and the clients behind them
    for c in clients:
        fams = c.get("fam") or {}
        attackish = {k: v for k, v in fams.items() if k != "probe"}
        if c.get("exploit_ok"):
            for x in c["exploit_ok"][:3]:
                out.append(("exploit_succeeded", c["_file"], x["line"], x["ts"], None,
                            f"{x['family']} from {c['_subject']}: {x['method']} {x['url']} answered {x['status']}", None))
            x = c["exploit_ok"][0]
            hyps.append({"ts": x["ts"], "kind": f"{x['family'].upper()} exploit answered {x['status']}", "confidence": "medium",
                         "ip": c["_subject"], "file_id": c["_file"], "line": x["line"],
                         "evidence": [f"{x['method']} {x['url']}"] + [f"{k} ×{v}" for k, v in attackish.items()]})

    # --- SSH footholds already found by the host layer
    for r in con.execute("SELECT rule, ts, file_id, line_no, snippet FROM findings WHERE rule IN "
                         "('brute_force_success','ssh_key_unknown_login') ORDER BY ts"):
        hyps.append({"ts": r["ts"], "kind": "SSH password guessed" if r["rule"] == "brute_force_success" else "SSH key that was later removed",
                     "confidence": "high" if r["rule"] == "brute_force_success" else "medium",
                     "ip": (re.search(r"\d{1,3}(?:\.\d{1,3}){3}", r["snippet"] or "") or [None])[0],
                     "file_id": r["file_id"], "line": r["line_no"], "evidence": [r["snippet"][:240]]})

    hyps = [h for h in hyps if h["ts"]]
    hyps.sort(key=lambda h: h["ts"])
    if hyps:
        h0 = hyps[0]
        h0["earliest"] = True
        e0 = az.ts_to_epoch(h0["ts"]) or 0
        # the foothold: the earliest high-confidence step within 6 h of the first successful one
        early = [h for h in hyps if (az.ts_to_epoch(h["ts"]) or 0) - e0 <= 6 * 3600]
        foot = next((h for h in early if h["confidence"] == "high"), h0)
        foot["likely"] = True
        for h in hyps:
            h["stage"] = "initial" if (az.ts_to_epoch(h["ts"]) or 0) - e0 <= 6 * 3600 else "later"
        compromise_start = min(compromise_start or h0["ts"], h0["ts"])
        pre = f" (first successful step: {h0['kind']} at {h0['ts']})" if foot is not h0 else ""
        out.append(("initial_access", foot["file_id"], foot["line"], foot["ts"], None,
                    f"Most likely way in: {foot['kind']} at {foot['ts']} from {foot['ip']}{pre} — " + "; ".join(foot["evidence"][:3]), None))

    # --- control over time: beacons, tunnels, long use
    for s in scripts:
        times = s.get("times") or []
        b = beacon(times)
        if b and b["span_h"] >= 1:
            out.append(("beaconing", s["_file"], s["_line"], b["first"], b["last"],
                        f"{s['ip']} polled {s['_subject']} every ~{human_interval(b['interval'])} (jitter {b['jitter']}%, "
                        f"{b['share']}% on time) {b['n']} times over {b['span_h']} h", json.dumps(b)))
            channel(kind="beacon (web)", target=s["_subject"], source=s["ip"], internal=_private(s["ip"]), n=b["n"],
                    first=b["first"], last=b["last"], interval=b["interval"], file_id=s["_file"], line=s["_line"])
        if s["n"] >= 200 and s["posts"] >= 0.9 * s["n"] and times and peak_per_minute(times) >= 40:
            pk = peak_per_minute(times)
            out.append(("http_tunnel", s["_file"], s["_line"], s["first"], s["last"],
                        f"{s['ip']} sent {s['posts']:,} POSTs to {s['_subject']} (up to {pk}/min, median response {s['size_median']} B)"
                        + (f"; {s['regeorg']} reGeorg-style connect/read/forward requests" if s.get("regeorg") else "")
                        + " — consistent with a SOCKS/HTTP tunnel through the script", None))
            channel(kind="HTTP tunnel", target=s["_subject"], source=s["ip"], internal=_private(s["ip"]), n=s["n"],
                    first=s["first"], last=s["last"], file_id=s["_file"], line=s["_line"])
        if s["first"] and s["last"] and s["n"] >= 10:
            days = ((az.ts_to_epoch(s["last"]) or 0) - (az.ts_to_epoch(s["first"]) or 0)) / 86400
            rare = (s.get("users") or 99) <= 3       # a script only a few clients ever touch
            if days >= 2 and (s["_subject"] in shell_urls or s.get("regeorg") or (rare and s["posts"] >= 0.5 * s["n"])):
                out.append(("long_control", s["_file"], s["_line"], s["first"], s["last"],
                            f"{s['ip']} kept using {s['_subject']} for {days:.1f} days ({s['n']:,} requests)", None))

    for r in con.execute("SELECT data, file_id, line_no FROM facts WHERE kind='conn_series'"):
        d = json.loads(r[0])
        b = beacon(d.get("times") or [])
        if b and b["span_h"] >= 1:
            out.append(("beaconing", r[1], r[2], b["first"], b["last"],
                        f"this host connected to {d['dst']} every ~{human_interval(b['interval'])} (jitter {b['jitter']}%) "
                        f"{b['n']} times over {b['span_h']} h (firewall log)", json.dumps(b)))
            channel(kind="beacon (outbound)", target=d["dst"], source="this host", internal=_private(d["dst"].rsplit(":", 1)[0]),
                    n=b["n"], first=b["first"], last=b["last"], interval=b["interval"], file_id=r[1], line=r[2])

    # --- the attacker's channels from inside the network, after the compromise began
    if compromise_start:
        for ch in channels:
            if ch["internal"] and ch["source"] not in ("this host",) and (ch["first"] or "") >= compromise_start:
                out.append(("internal_control", ch["file_id"], ch["line"], ch["first"], ch["last"],
                            f"internal address {ch['source']} used the {ch['kind']} {ch['target']} {ch['n']:,} times "
                            f"({ch['first']} → {ch['last']}), after the compromise began at {compromise_start}", None))
        attacker_accounts = {r[0] for r in con.execute(
            "SELECT subject FROM facts WHERE kind='account_change' AND data LIKE '%created%'")}
        attacker_accounts |= {m for (sn,) in con.execute("SELECT snippet FROM findings WHERE rule IN ('uid0_account','account_added')")
                              for m in re.findall(r"name=(\w[\w.-]*)|^(\w[\w.-]*) \(UID", sn or "") for m in m if m}
        seen = set()
        for r in con.execute("SELECT subject, ts, file_id, line_no, data FROM facts WHERE kind='login' AND ts >= ? ORDER BY ts",
                             (compromise_start,)):
            d = json.loads(r["data"])
            ip = d.get("ip") or ""
            if d.get("result") not in ("success", "session") or not _private(ip) or ip in ("127.0.0.1", "::1"):
                continue
            key = (r["subject"], ip)
            if key in seen:
                continue
            seen.add(key)
            earlier = con.execute("SELECT 1 FROM facts WHERE kind='login' AND ts < ? AND data LIKE ? LIMIT 1",
                                  (compromise_start, f'%"{ip}"%')).fetchone()
            if r["subject"] in attacker_accounts or not earlier:
                strong = r["subject"] in attacker_accounts
                why = "attacker-created account" if strong else "address never seen before the compromise"
                out.append(("internal_control" if strong else "internal_new_source", r["file_id"], r["line_no"], r["ts"], None,
                            f"{r['subject']} logged in from internal {ip} at {r['ts']} ({why})", None))
                channel(kind="SSH", target=r["subject"], source=ip, internal=True, n=1, first=r["ts"], last=r["ts"],
                        file_id=r["file_id"], line=r["line_no"])

    con.executemany("INSERT INTO facts(kind, scope, file_id, line_no, ts, subject, data) VALUES(?,?,?,?,?,?,?)",
                    [("initial_access", "case", h.get("file_id"), h.get("line"), h["ts"], h["kind"], json.dumps(h)) for h in hyps[:40]]
                    + [("channel", "case", c.get("file_id"), c.get("line"), c.get("first"), c["kind"], json.dumps(c)) for c in channels[:500]])
    if compromise_start:
        con.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('compromise_start', ?)", (compromise_start,))
    return out
