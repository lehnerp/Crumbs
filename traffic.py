"""
Mail and connection traffic over time, and the flood / starvation episodes hidden in it.

Per file, every MTA, firewall and kernel event is counted per minute (with who, where to and
from which script). Across the case, minutes far above the machine's normal rate are grouped
into numbered episodes: SMTP floods (mass mail through this host's MTA), outbound SMTP
connection floods or starvation (many connections from this host to other mail servers, few
messages), saturation of this host's own SMTP service, and resource starvation (OOM, full
conntrack table, SYN flood warnings, full disk, fork failures).
"""
import json
import re
from collections import Counter

import analyzers as az

SMTP_PORTS = {"25", "465", "587", "2525"}

# --- Exim mainlog ----------------------------------------------------------------
R_EXIM = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(?:\.\d+)?(?: [+-]\d{4})? (?:\[\d+\] )?(?:(\w{6}-\w{6,11}-\w{2,4}) )?(.*)$")
R_KV_U = re.compile(r"\bU=(\S+)")
R_KV_H = re.compile(r"\bH=(?:\(([^)]*)\) )?([\w.-]*)\s*(?:\(([^)]*)\)\s*)?\[([0-9a-fA-F.:]+)\]")
R_EXIM_CWD = re.compile(r"cwd=(\S+) \d+ args: (.*)")
R_EXIM_CONN = re.compile(r"SMTP connection from .*?\[([0-9a-fA-F.:]+)\]")
# --- Postfix / sendmail / msmtp (syslog format) ------------------------------------
R_PF = re.compile(r"postfix/(?:[\w.-]+/)?([\w-]+)\[\d+\]: (.*)")
R_PF_CONN = re.compile(r"^connect from \S*?\[([0-9a-fA-F.:]+)\]")
R_PF_LOST = re.compile(r"^(lost connection|timeout) after (\w+)(?: \([^)]*\))? from \S*?\[([0-9a-fA-F.:]+)\]")
R_PF_PICKUP = re.compile(r"^\w+: uid=(\d+) from=<([^>]*)>")
R_PF_QMGR = re.compile(r"^\w+: from=<([^>]*)>, size=(\d+), nrcpt=(\d+)")
R_PF_TO = re.compile(r"^\w+: to=<([^>]*)>,.*?relay=([^,\s]+).*?status=(\w+)")
R_MSMTP = re.compile(r"msmtp: host=(\S+).*?recipients=(\S+).*?(?:smtpstatus=(\d+)|exitcode=(\w+))")
R_SM = re.compile(r"(?:sm-mta|sendmail)\[\d+\]: \w+: (?:to=<?([^,>\s]+)>?,.*?stat=(\w+)|from=<?([^,>\s]*)>?, size=\d+, .*?nrcpts=(\d+))")
# --- network and resources ----------------------------------------------------------
R_FW = re.compile(r"\bIN=(\S*) OUT=(\S*).*?\bSRC=([0-9a-fA-F.:]+) DST=([0-9a-fA-F.:]+).*?\bPROTO=(\w+)(?:.*?\bSPT=(\d+) DPT=(\d+))?")
R_CT = re.compile(r"\[NEW\] tcp\s+\d+\s+\d+\s+\w+\s+src=([0-9a-fA-F.:]+) dst=([0-9a-fA-F.:]+) sport=\d+ dport=(\d+)")
RESOURCE = [
    (re.compile(r"Possible SYN flooding on port (\d+)", re.I), "syn_flood"),
    (re.compile(r"nf_conntrack: (?:nf_conntrack: )?table full, dropping packet", re.I), "conntrack_full"),
    (re.compile(r"Out of memory: Kill(?:ed)? process|invoked oom-killer", re.I), "oom"),
    (re.compile(r"No space left on device|insufficient system storage|disk space .*(?:low|exhausted)", re.I), "nospace"),
    (re.compile(r"fork: (?:retry: )?(?:Resource temporarily unavailable|Cannot allocate memory)", re.I), "fork_fail"),
    (re.compile(r"Too many open files", re.I), "fd_exhaust"),
    (re.compile(r"TCP: out of memory|neighbour table overflow|page allocation failure", re.I), "kernel_mem"),
]
RESOURCE_KEYS = {k for _r, k in RESOURCE}

SNIFF = [
    (re.compile(r"(?i)(device \S+ |: )?entered promiscuous mode|type=ANOM_PROMISCUOUS"), "promisc"),
    (re.compile(r"(?i)left promiscuous mode"), "promisc_off"),
    (re.compile(r"(?i)is using my IP address|\bARP\b[^\n]*(?:flip flop|changed ethernet address|moved from)|arpwatch[^\n]*(?:flip flop|changed ethernet|new activity|reused old)|own address as source|duplicate (?:IP )?address \S+ detected"), "arp_warn"),
    (re.compile(r"(?i)net\.ipv[46][^\n]*(?:ip_forward|forwarding)\s*=\s*1|/proc/sys/net/ipv[46]/(?:ip_forward|conf/\S+/forwarding)"), "forward_on"),
    (re.compile(r"(?i)martian source|redirected? host|ICMP redirect"), "redirect"),
]
SNIFF_KEYS = {k for _r, k in SNIFF}
# --- DHCP flood / starvation detection ------------------------------------
R_DHCP_DISC = re.compile(
    r"dhcpd?\[\d+\]:\s+DHCPDISCOVER from ([0-9a-f:]{17}) via (\S+)"
    r"|dnsmasq-dhcp\[\d+\]:\s+\d+ DHCPDISCOVER\((\S+)\)\s+([0-9a-f:]{17})", re.I)
R_DHCP_ACK  = re.compile(
    r"dhcpd?\[\d+\]:\s+DHCPACK on ([0-9.]+) to ([0-9a-f:]{17})", re.I)
R_DHCP_NOFREE = re.compile(r"dhcpd?\[\d+\]:\s+no free leases", re.I)
R_DHCP_TOOL = re.compile(
    r"\byersinia\b|\bdhcpstarv\b|\bdhcpig\b|\bdhcpflood\b|\bdhcpstress\b"
    r"|\bdhcpd?\s.*starvation\s+attack", re.I)

R_DNSQ = re.compile(r"dnsmasq(?:\[\d+\])?: query\[\w+\] (\S+) from|\bquery: (\S+) IN \w+")

MAIL_KINDS = {"mail_log", "auth_log"}
NET_KINDS = {"kern_log", "auth_log"}


def _dom(addr):
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else (addr.lower() or "(empty)")


class Traffic:
    """Per-file per-minute counters."""

    def __init__(self, kind):
        self.kind = kind
        self.m = {}          # minute -> dict
        self.submits = {}    # (cwd, args) -> [count, first_ts, last_ts, line, user]
        self.queued = []     # exim -H spool headers
        self.hdr = []
        self.series = {}     # "dst:port" -> [first_line, [epoch...]]  (outbound, any port)
        self.qnames = []     # (line, ts, qname) from dnsmasq / bind query logs

    def _b(self, ts, n):
        mm = ts[:16]
        b = self.m.get(mm)
        if b is None:
            b = self.m[mm] = {"c": Counter(), "first": n, "last": n, "dom": Counter(), "user": Counter(),
                              "peer": Counter(), "dst": Counter(), "relay": Counter(), "sender": Counter()}
        b["last"] = n
        return b

    def feed(self, n, line, ts):
        if self.kind == "mail_queue":
            if len(self.hdr) < 6:
                self.hdr.append((n, line))
            return
        if not ts:
            return
        low = None
        if self.kind in ("mail_log", "auth_log"):
            if line[:4].isdigit() and (" <= " in line or " => " in line or " -> " in line or " == " in line or " ** " in line
                                       or "SMTP" in line or "cwd=" in line or "connection" in line or "frozen" in line):
                self._exim(n, line, ts)
                return
            if "postfix/" in line:
                self._postfix(n, line, ts)
                return
            if "msmtp" in line or "sm-mta" in line or "sendmail[" in line:
                self._other_mta(n, line, ts)
                return
        if "DPT=" in line or "[NEW] tcp" in line:
            self._net(n, line, ts)
            return
        if "query[" in line or "query: " in line:
            m = R_DNSQ.search(line)
            if m and len(self.qnames) < 300000:
                self.qnames.append((n, ts, m.group(1) or m.group(2)))
                return
        low = line
        for rx, key in RESOURCE:
            if rx.search(low):
                b = self._b(ts, n)
                b["c"][key] += 1
                m = rx.search(low)
                if key == "syn_flood" and m.groups():
                    b["dst"][f"port {m.group(1)}"] += 1
                return
        for rx, key in SNIFF:
            if rx.search(low):
                b = self._b(ts, n)
                b["c"][key] += 1
                m = re.search(r"\b(?:auid|uid)=(\d+)", low)
                if m:
                    b["user"][f"uid {m.group(1)}"] += 1
                m = re.search(r"\bdev=(\S+)|device (\S+)", low)
                if m:
                    b["peer"][m.group(1) or m.group(2)] += 1
                return

    # --- MTAs
    def _exim(self, n, line, ts):
        m = R_EXIM.match(line)
        if not m:
            return
        rest = m.group(3)
        b = None
        if rest.startswith("<= "):
            b = self._b(ts, n)
            b["c"]["msg"] += 1
            snd = rest[3:].split(" ", 1)[0]
            b["sender"][snd] += 1
            u = R_KV_U.search(rest)
            if u:
                b["user"][u.group(1)] += 1
            h = R_KV_H.search(rest)
            if h:
                b["peer"][h.group(4)] += 1
        elif rest[:3] in ("=> ", "-> ", "*> ", "** ", "== "):
            b = self._b(ts, n)
            key = {"** ": "fail", "== ": "defer"}.get(rest[:3], "out")
            b["c"][key] += 1
            rcpt = rest[3:].split(" ", 1)[0]
            b["dom"][_dom(rcpt)] += 1
            h = R_KV_H.search(rest)
            if h:
                b["relay"][h.group(2) or h.group(4)] += 1
        elif rest.startswith("cwd="):
            c = R_EXIM_CWD.match(rest)
            if c:
                key = (c.group(1), c.group(2)[:300])
                s = self.submits.setdefault(key, [0, ts, ts, n])
                s[0] += 1
                s[2] = ts
        elif "SMTP connection from" in rest:
            c = R_EXIM_CONN.search(rest)
            b = self._b(ts, n)
            b["c"]["conn"] += 1
            if c:
                b["peer"][c.group(1)] += 1
        elif "too many connections" in rest or "refused" in rest and "connection" in rest.lower():
            self._b(ts, n)["c"]["refused"] += 1
        elif "SMTP command timeout" in rest or "SMTP data timeout" in rest:
            self._b(ts, n)["c"]["timeout"] += 1
        elif "unexpected disconnection" in rest or "SMTP connection lost" in rest or "lost while reading" in rest:
            self._b(ts, n)["c"]["drop"] += 1
        elif "rejected RCPT" in rest or "relay not permitted" in rest or "rejected after DATA" in rest:
            self._b(ts, n)["c"]["reject"] += 1
        elif "frozen" in rest.lower():
            self._b(ts, n)["c"]["frozen"] += 1
        elif "No space" in rest or "space on disk" in rest:
            self._b(ts, n)["c"]["nospace"] += 1

    def _postfix(self, n, line, ts):
        m = R_PF.search(line)
        if not m:
            return
        prog, msg = m.groups()
        if prog in ("smtpd", "postscreen"):
            c = R_PF_CONN.match(msg)
            if c:
                b = self._b(ts, n)
                b["c"]["conn"] += 1
                b["peer"][c.group(1)] += 1
                return
            c = R_PF_LOST.match(msg)
            if c:
                b = self._b(ts, n)
                b["c"]["drop" if c.group(1) == "lost connection" else "timeout"] += 1
                b["peer"][c.group(3)] += 1
                return
            if "too many connections" in msg or "limit exceeded" in msg:
                self._b(ts, n)["c"]["refused"] += 1
            elif "NOQUEUE: reject" in msg:
                self._b(ts, n)["c"]["reject"] += 1
        elif prog == "master" and "reached its process limit" in msg:
            self._b(ts, n)["c"]["limit"] += 1
        elif prog == "pickup":
            c = R_PF_PICKUP.match(msg)
            if c:
                b = self._b(ts, n)
                b["user"][f"uid {c.group(1)}"] += 1
                b["sender"][c.group(2)] += 1
        elif prog == "qmgr":
            c = R_PF_QMGR.match(msg)
            if c:
                b = self._b(ts, n)
                b["c"]["msg"] += 1
                b["sender"][c.group(1)] += 1
        elif prog in ("smtp", "lmtp", "local", "virtual", "error", "discard", "relay"):
            c = R_PF_TO.match(msg)
            if c:
                b = self._b(ts, n)
                st = c.group(3)
                b["c"]["out" if st == "sent" else "defer" if st == "deferred" else "fail"] += 1
                b["dom"][_dom(c.group(1))] += 1
                b["relay"][c.group(2).split("[")[0]] += 1
        if "No space left" in msg or "insufficient system storage" in msg:
            self._b(ts, n)["c"]["nospace"] += 1

    def _other_mta(self, n, line, ts):
        m = R_MSMTP.search(line)
        if m:
            b = self._b(ts, n)
            b["c"]["msg"] += 1
            ok = m.group(3) and m.group(3).startswith("2")
            for r in m.group(2).split(","):
                b["c"]["out" if ok else "fail"] += 1
                b["dom"][_dom(r)] += 1
            b["relay"][m.group(1)] += 1
            return
        m = R_SM.search(line)
        if m:
            b = self._b(ts, n)
            if m.group(1):
                b["c"]["out" if m.group(2) == "Sent" else "defer" if m.group(2) == "Deferred" else "fail"] += 1
                b["dom"][_dom(m.group(1))] += 1
            else:
                b["c"]["msg"] += 1
                b["sender"][m.group(3)] += 1

    def _net(self, n, line, ts):
        m = R_FW.search(line)
        if m:
            iface_in, iface_out, src, dst, proto, spt, dpt = m.groups()
            if iface_out and not iface_in and dpt and ("SYN" in line or proto == "UDP"):
                key = f"{dst}:{dpt}"
                ser = self.series.get(key)
                if ser is None and len(self.series) < 5000:
                    ser = self.series[key] = [n, []]
                if ser is not None and len(ser[1]) < 8000:
                    e = az.ts_to_epoch(ts)
                    if e is not None:
                        ser[1].append(int(e))
            if dpt in SMTP_PORTS:
                b = self._b(ts, n)
                if iface_out and not iface_in:
                    b["c"]["net_out"] += 1
                    b["dst"][f"{dst}:{dpt}"] += 1
                else:
                    b["c"]["net_in"] += 1
                    b["peer"][src] += 1
            return
        m = R_CT.search(line)
        if m and m.group(3) in SMTP_PORTS:
            b = self._b(ts, n)
            b["c"]["net_out"] += 1
            b["dst"][f"{m.group(2)}:{m.group(3)}"] += 1

    def feed_dhcp(self, ts, n, line):
        """Parse one syslog line for DHCP flood signals."""
        m = R_DHCP_DISC.search(line)
        if m:
            mac = (m.group(1) or m.group(4) or "").lower()
            iface = m.group(2) or m.group(3) or ""
            b = self._b(ts, n)
            b["c"]["dhcp_disc"] = b["c"].get("dhcp_disc", 0) + 1
            b.setdefault("dhcp_macs", set()).add(mac)
            b.setdefault("dhcp_iface", iface)
            return
        m = R_DHCP_NOFREE.search(line)
        if m:
            b = self._b(ts, n)
            b["c"]["dhcp_nofree"] = b["c"].get("dhcp_nofree", 0) + 1
            return
        if R_DHCP_ACK.search(line):
            b = self._b(ts, n)
            b["c"]["dhcp_ack"] = b["c"].get("dhcp_ack", 0) + 1

    def facts(self):

        out = []
        for mm, b in self.m.items():
            if "dhcp_macs" in b:
                b["dhcp_macs"] = list(b["dhcp_macs"])
            dhcp_extra = {}
            if b.get("dhcp_macs"):
                dhcp_extra["dhcp_macs"] = b["dhcp_macs"]
            if b.get("dhcp_iface"):
                dhcp_extra["dhcp_iface"] = b["dhcp_iface"]
            out.append(("traffic_min", b["first"], mm + ":00", mm, {
                "src": self.kind, "c": dict(b["c"]), "first": b["first"], "last": b["last"],
                **dhcp_extra,
                **{k: dict(b[k].most_common(8)) for k in ("dom", "user", "peer", "dst", "relay", "sender") if b[k]}}))
        for key, (n0, times) in self.series.items():
            if len(times) >= 8:
                out.append(("conn_series", n0, az.epoch_to_ts(times[0]), key, {"dst": key, "times": times}))
        for (cwd, args), (cnt, a, z, n) in self.submits.items():
            out.append(("mail_submit", n, a, cwd, {"args": args, "count": cnt, "last": z}))
        if self.kind == "mail_queue" and len(self.hdr) >= 4:
            try:
                user = self.hdr[1][1].split()[0]
                sender = self.hdr[2][1].strip("<>")
                t = az.epoch_to_ts(int(self.hdr[3][1].split()[0]))
                out.append(("mail_queued", 1, t, user, {"sender": sender}))
            except (ValueError, IndexError):
                pass
        return out


# ------------------------------------------------------------- episodes ---
SERIES = {
    # name: (event keys, label, rule, min events per minute, minimum total)
    "flood": (("msg", "out", "defer", "fail"), "SMTP flood", "smtp_flood", 30, 150),
    "saturation": (("conn", "drop", "timeout", "refused", "limit", "net_in"), "SMTP service saturated", "smtp_saturation_episode", 30, 150),
    "outbound": (("net_out",), "Outbound SMTP connection flood", "outbound_smtp_flood", 30, 150),
    "resource": (tuple(sorted(RESOURCE_KEYS)), "Resource starvation", "resource_starvation", 1, 3),
}
EPISODE_RULES = {
    "smtp_flood": ("high", "dos", "SMTP flood: mass mail sent through this host"),
    "outbound_smtp_flood": ("high", "dos", "Outbound SMTP connection flood / starvation of other mail servers"),
    "smtp_saturation_episode": ("high", "dos", "SMTP service flooded or starved (connections held, dropped or refused)"),
    "resource_starvation": ("medium", "dos", "Resource starvation (memory, connections, disk, processes)"),
    "mail_queue_backlog": ("medium", "dos", "Large mail queue left behind"),
    "dhcp_starvation": ("high", "dos", "DHCP pool exhaustion / starvation attack — IP address pool was flooded"),
    "dhcp_flood": ("high", "dos", "DHCP DISCOVER flood — unusually high rate of DHCP discovery requests"),
    "sniffing_episode": ("high", "sniffing", "Network eavesdropping (packet capture / promiscuous mode)"),
    "mitm_episode": ("high", "sniffing", "Traffic manipulation / man-in-the-middle"),
}

SNIFF_RULES = {"promiscuous_mode", "packet_capture", "promiscuous", "packet_capture_file", "cleartext_creds"}
MITM_RULES = {"arp_spoof", "traffic_redirect", "dns_tamper", "rogue_ca", "arp_conflict"}


def _ns_ts(ns):
    return az.epoch_to_ts(ns / 1e9) if ns else None


def _minutes(ts):
    e = az.ts_to_epoch(ts)
    return int(e // 60) if e is not None else None


def detect_episodes(con, files):
    """Group per-minute traffic into numbered episodes. Writes 'episode' facts (scope 'case')
    and returns findings tuples (rule, file_id, line_no, ts, ts_end, snippet, detail)."""
    con.execute("DELETE FROM facts WHERE scope='case' AND kind='episode'")
    rows = []
    kinds_present = set()
    for r in con.execute("SELECT file_id, subject, data FROM facts WHERE kind='traffic_min' AND scope='file'"):
        d = json.loads(r["data"])
        rows.append((r["file_id"], r["subject"], d))
        kinds_present.add(d["src"])
    subs = [dict(json.loads(r["data"]), cwd=r["subject"], ts=r["ts"], file_id=r["file_id"], line=r["line_no"])
            for r in con.execute("SELECT subject, ts, data, file_id, line_no FROM facts WHERE kind='mail_submit'")]
    out = []
    raw = []
    MAIL_KEYS = {"msg", "out", "defer", "fail", "conn", "drop", "timeout", "refused", "limit", "reject", "frozen"}

    def allowed(src, key):
        # syslog repeats what mail.log / kern.log already hold: use it only when they are missing
        if src != "auth_log":
            return True
        return "mail_log" not in kinds_present if key in MAIL_KEYS else "kern_log" not in kinds_present

    all_min = [_minutes(mm + ":00") for _f, mm, _d in rows]
    span = (max(all_min) - min(all_min) + 1) if all_min else 1

    for name, (keys, label, rule, min_rate, min_total) in SERIES.items():
        per_min, contrib = Counter(), {}
        for fid, mm, d in rows:
            v = sum(d["c"].get(k, 0) for k in keys if allowed(d["src"], k))
            if not v:
                continue
            m = _minutes(mm + ":00")
            per_min[m] += v
            contrib.setdefault(m, []).append((fid, d, v))
        if not per_min:
            continue
        # normal level = 90th percentile per minute over the whole logged period (quiet minutes count as 0)
        nz = sorted(per_min.values())
        zeros = span - len(nz)
        k = int(span * 0.9)
        p90 = 0 if k < zeros else nz[min(len(nz) - 1, k - zeros)]
        thr = max(min_rate, 5 * p90)
        hot = sorted(m for m, v in per_min.items() if v >= thr)
        groups, cur = [], []
        gap = 10 if name == "resource" else 3
        for m in hot:
            if cur and m - cur[-1] > gap:
                groups.append(cur)
                cur = []
            cur.append(m)
        if cur:
            groups.append(cur)
        for g in groups:
            # widen to the neighbouring active minutes that belong to the same burst
            a, z = g[0], g[-1]
            while per_min.get(a - 1, 0) >= max(1, thr / 4):
                a -= 1
            while per_min.get(z + 1, 0) >= max(1, thr / 4):
                z += 1
            span_m = [m for m in range(a, z + 1) if m in per_min]
            total = sum(per_min[m] for m in span_m)
            if total < min_total:
                continue
            raw.append({"series": name, "label": label, "rule": rule, "a": a, "z": z, "total": total,
                        "peak": max(per_min[m] for m in span_m),
                        "contrib": [c for m in span_m for c in contrib[m]],
                        "normal": (sum(per_min.values()) - total) / max(1, span - len(span_m))})
    incidents = []
    # merge aspects that overlap in time into one incident
    raw.sort(key=lambda e: e["a"])
    for e in raw:
        if incidents and e["a"] <= incidents[-1]["z"] + 10:
            inc = incidents[-1]
            inc["z"] = max(inc["z"], e["z"])
            inc["aspects"].append(e)
        else:
            incidents.append({"a": e["a"], "z": e["z"], "aspects": [e]})
    fmt = lambda m: az.epoch_to_ts(m * 60)
    for i, inc in enumerate(incidents, 1):
        start, end = fmt(inc["a"]), fmt(inc["z"])[:16] + ":59"
        dur = inc["z"] - inc["a"] + 1
        aspects = []
        efiles = Counter()
        firsts = {}
        tot = Counter()
        agg = {k: Counter() for k in ("dom", "user", "peer", "dst", "relay", "sender")}
        seen = set()
        for e in sorted(inc["aspects"], key=lambda e: -e["total"]):
            aspects.append({"series": e["series"], "label": e["label"], "rule": e["rule"], "total": e["total"],
                            "peak": e["peak"], "normal": round(e["normal"], 4)})
            for fid, d, v in e["contrib"]:
                efiles[fid] += v
                firsts[fid] = min(firsts.get(fid, d["first"]), d["first"])
                if id(d) in seen:
                    continue
                seen.add(id(d))
                for k, c in d["c"].items():
                    if allowed(d["src"], k):
                        tot[k] += c
                for k in agg:
                    for x, c in d.get(k, {}).items():
                        agg[k][x] += c
        # per-minute series for a small chart (episode ± 20 min)
        chart = Counter()
        lo, hi = inc["a"] - 20, inc["z"] + 20
        for fid, mm, d in rows:
            m = _minutes(mm + ":00")
            if lo <= m <= hi:
                chart[m] += sum(d["c"].values())
        scripts = [s for s in subs if s["ts"] and start <= s["ts"] <= end or (s.get("last") and start <= s["last"] <= end)]
        # what set it off: related signals from 15 minutes before the start to the end
        lead = az.epoch_to_ts((inc["a"] - 15) * 60)
        related = [dict(r) for r in con.execute(
            "SELECT fi.rule, fi.severity, fi.ts, fi.snippet, fi.file_id, fi.line_no, f.rel FROM findings fi "
            "JOIN files f ON f.id = fi.file_id WHERE (fi.ts BETWEEN ? AND ? AND (fi.category IN ('dos','webshell','c2','tooling') "
            "OR fi.rule IN ('web_cmd_param', 'lolbin', 'reverse_shell')) "
            "OR (fi.ts IS NULL AND f.mtime_ns BETWEEN ? AND ? AND fi.category IN ('dos', 'webshell'))) AND fi.scope = 'line' "
            "AND fi.rule NOT IN ('resource_exhaustion', 'smtp_saturation', 'auth_failure', 'sudo_command', 'ssh_login') "
            "ORDER BY coalesce(fi.ts, '') LIMIT 40", (lead, end, (inc["a"] - 15) * 60 * 10**9, (inc["z"] + 1) * 60 * 10**9))]
        for r in related:
            if not r["ts"]:
                r["snippet"] = "(file last changed in this window) " + r["snippet"]
        main = aspects[0]
        title = " + ".join(a["label"] for a in aspects)
        msgs, rcpts = tot["msg"], tot["out"] + tot["defer"] + tot["fail"]
        bits = [f"{dur} min"]
        if msgs:
            bits.append(f"{msgs:,} messages")
        if rcpts:
            bits.append(f"{rcpts:,} delivery attempts ({tot['out']:,} sent, {tot['defer']:,} deferred, {tot['fail']:,} failed)"
                        f" to {len(agg['dom'])} domains")
        if tot["net_out"]:
            bits.append(f"{tot['net_out']:,} outbound SMTP connections to {len(agg['dst'])} server(s): "
                        + ", ".join(x for x, _ in agg["dst"].most_common(3)))
        sat = sum(tot[k] for k in ("conn", "drop", "timeout", "refused", "limit", "net_in"))
        if sat:
            bits.append(f"{sat:,} inbound SMTP connection events ({tot['drop'] + tot['timeout']:,} dropped or timed out, "
                        f"{tot['refused'] + tot['limit']:,} refused or at the limit)")
        res = [k for k in sorted(RESOURCE_KEYS) if tot[k]]
        if res:
            bits.append("resources: " + ", ".join(f"{k.replace('_', ' ')} ×{tot[k]}" for k in res))
        who = [u for u, _ in agg["user"].most_common(3)]
        if who:
            bits.append("submitted by " + ", ".join(who))
        if scripts:
            bits.append("from " + ", ".join(sorted({s["cwd"] for s in scripts}))[:200])
        if main["series"] != "resource":
            nm = main["normal"]
            normal = "almost never" if nm < 1 / 1440 else f"about {nm * 60:.1f}/hour" if nm < 1 else f"about {nm:.0f}/min"
            bits.append(f"peak {main['peak']:,}/min; normally {normal}")
        summary = f"Episode #{i}, {title}: " + "; ".join(bits)
        data = {"n": i, "kind": "flood", "title": title, "start": start, "end": end, "minutes": dur, "aspects": aspects,
                "totals": dict(tot), "files": [{"file_id": f, "events": c, "first_line": firsts[f]} for f, c in efiles.most_common()],
                "top": {k: agg[k].most_common(10) for k in agg},
                "related": [{"rule": r["rule"], "description": az.RULE_INFO.get(r["rule"], {}).get("description", r["rule"]),
                             "severity": r["severity"], "ts": r["ts"], "snippet": r["snippet"][:300], "file_id": r["file_id"],
                             "line": r["line_no"], "rel": r["rel"]} for r in related],
                "scripts": [{"cwd": s["cwd"], "args": s["args"], "count": s["count"], "file_id": s["file_id"], "line": s["line"]} for s in scripts[:20]],
                "chart": [[fmt(m)[11:16], chart.get(m, 0), inc["a"] <= m <= inc["z"]] for m in range(lo, hi + 1)],
                "summary": summary}
        con.execute("INSERT INTO facts(kind, scope, file_id, line_no, ts, subject, data) VALUES('episode','case',?,?,?,?,?)",
                    (efiles.most_common(1)[0][0], firsts[efiles.most_common(1)[0][0]], start, str(i), json.dumps(data)))
        det = json.dumps({"episode": i, "end": end})
        for fid, _c in efiles.most_common(10):  # tag the episode in every file that shows it
            out.append((main["rule"], fid, firsts[fid], start, end, summary, det))
    # queue left behind
    q = con.execute("SELECT count(*) n, min(ts) a, max(ts) b, group_concat(DISTINCT subject) u FROM facts WHERE kind='mail_queued'").fetchone()
    qfiles = [f for f in files if re.search(r"(?:^|/)var/spool/(?:exim4/input/.+-H|postfix/(?:deferred|active|incoming|hold|maildrop)/.)", f["rel"])]
    if len(qfiles) >= 20:
        out.append(("mail_queue_backlog", qfiles[0]["id"], None, q["a"], q["b"],
                    f"{len(qfiles):,} messages still queued" + (f", queued {q['a']} to {q['b']} UTC by {q['u']}" if q["n"] else ""), None))

    dhcp_out, next_ep = detect_dhcp_flood(con, next_episode=len(incidents) + 1)
    out += dhcp_out
    out += detect_sniffing(con, next_episode=next_ep)
    return out


def detect_dhcp_flood(con, next_episode=1):
    """Group DHCP burst minutes into starvation/flood episodes.

    A minute qualifies when DHCP DISCOVERs are far above the host's normal rate,
    or when 'no free leases' errors appear.  Unique MAC addresses seen in the window
    are reported as suspects: in a starvation attack the MAC pool is spoofed, but
    the stream still arrives from one physical port/interface, and the MAC OUI prefix
    is often constant (tools like yersinia default to de:ad:be:ef:xx:xx).
    """
    out = []
    # pull per-minute DHCP counts from traffic_min facts
    rows = []
    for r in con.execute("SELECT file_id, subject, data FROM facts WHERE kind='traffic_min' AND scope='file'"):
        d = json.loads(r["data"])
        disc = d["c"].get("dhcp_disc", 0)
        nofree = d["c"].get("dhcp_nofree", 0)
        if disc + nofree == 0:
            continue
        rows.append({"fid": r["file_id"], "mm": r["subject"], "disc": disc, "nofree": nofree,
                     "ack": d["c"].get("dhcp_ack", 0), "macs": d.get("dhcp_macs", []),
                     "iface": d.get("dhcp_iface", ""), "first": d.get("first"), "last": d.get("last")})

    if not rows:
        return out, next_episode

    # normal baseline = 90th percentile
    all_disc = sorted(r["disc"] for r in rows)
    p90 = all_disc[int(len(all_disc) * 0.9)] if all_disc else 0
    thr = max(10, 5 * p90)

    # group hot minutes (≥threshold DISCOVERs, or any no-free-leases) into episodes
    per_min = {}
    for r in rows:
        m = _minutes(r["mm"] + ":00")
        if m is None: continue
        if m not in per_min:
            per_min[m] = {"disc": 0, "nofree": 0, "ack": 0, "macs": set(), "rows": []}
        per_min[m]["disc"]   += r["disc"]
        per_min[m]["nofree"] += r["nofree"]
        per_min[m]["ack"]    += r["ack"]
        per_min[m]["macs"].update(r["macs"])
        per_min[m]["rows"].append(r)

    hot = sorted(m for m, v in per_min.items() if v["disc"] >= thr or v["nofree"] >= 3)
    if not hot:
        return out, next_episode

    # merge into burst groups (≤5 minute gap)
    groups, cur = [], []
    for m in hot:
        if cur and m - cur[-1] > 5:
            groups.append(cur); cur = []
        cur.append(m)
    if cur: groups.append(cur)

    fmt = lambda m: az.epoch_to_ts(m * 60)
    for g in groups:
        a, z = g[0], g[-1]
        # widen to neighbouring active minutes
        while per_min.get(a - 1, {}).get("disc", 0) >= max(1, thr // 4): a -= 1
        while per_min.get(z + 1, {}).get("disc", 0) >= max(1, thr // 4): z += 1

        span = list(range(a, z + 1))
        total_disc   = sum(per_min.get(m, {}).get("disc", 0) for m in span)
        total_nofree = sum(per_min.get(m, {}).get("nofree", 0) for m in span)
        total_ack    = sum(per_min.get(m, {}).get("ack", 0) for m in span)
        all_macs = set()
        for m in span:
            all_macs.update(per_min.get(m, {}).get("macs", set()))
        ifaces = {per_min.get(m, {}).get("rows", [{}])[0].get("iface", "") for m in span if per_min.get(m)} - {""}

        start, end = fmt(a), fmt(z)[:16] + ":59"
        exhausted = total_nofree > 0

        # suspect analysis: in starvation attacks MACs share a common OUI prefix
        suspect_oui = None
        oui_counts = Counter(mac[:8] for mac in all_macs if len(mac) >= 8)
        if oui_counts:
            top_oui, top_count = oui_counts.most_common(1)[0]
            if top_count >= len(all_macs) * 0.6:
                suspect_oui = top_oui

        # also look for correlated findings (yersinia, dhcpig run at the same time)
        lead = az.epoch_to_ts((a - 15) * 60)
        related = [dict(r) for r in con.execute(
            "SELECT fi.rule, fi.severity, fi.ts, fi.snippet, fi.file_id, fi.line_no, f.rel "
            "FROM findings fi JOIN files f ON f.id=fi.file_id "
            "WHERE fi.ts BETWEEN ? AND ? AND (fi.rule IN ('flood_tool','dos_tool') "
            "OR fi.snippet LIKE '%yersinia%' OR fi.snippet LIKE '%dhcpig%' OR fi.snippet LIKE '%dhcpstarv%') "
            "ORDER BY fi.ts LIMIT 20", (lead, end))]

        # files that contributed
        fid_first = {}
        for m in span:
            for r in per_min.get(m, {}).get("rows", []):
                fid = r["fid"]
                if fid not in fid_first or (r["first"] or "9") < fid_first[fid]:
                    fid_first[fid] = r.get("first", "")

        n = next_episode
        next_episode += 1

        title = ("DHCP pool exhaustion / starvation" if exhausted else "DHCP DISCOVER flood")
        if len(ifaces) == 1:
            title += f" on {list(ifaces)[0]}"

        bits = [f"{z - a + 1} min", f"{total_disc:,} DISCOVER requests from {len(all_macs)} unique MACs"]
        if exhausted:
            bits.append(f"pool exhausted ({total_nofree:,} 'no free leases')")
        if total_ack:
            bits.append(f"{total_ack:,} leases granted before pool ran out")
        if suspect_oui:
            bits.append(f"suspect MAC prefix {suspect_oui} ({top_count}/{len(all_macs)} MACs share it — tool-generated)")
        if ifaces:
            bits.append(f"interface: {', '.join(ifaces)}")
        summary = f"Episode #{n}, {title}: " + "; ".join(bits)

        data = {
            "n": n, "title": title, "start": start, "end": end,
            "minutes": z - a + 1, "kind": "dhcp_flood",
            "aspects": [{"series": "dhcp_flood" if not exhausted else "dhcp_starvation",
                         "label": title, "rule": "dhcp_starvation" if exhausted else "dhcp_flood",
                         "total": total_disc, "peak": max(per_min.get(m, {}).get("disc", 0) for m in span),
                         "normal": p90}],
            "totals": {"disc": total_disc, "nofree": total_nofree, "ack": total_ack},
            "suspects": {
                "unique_macs": len(all_macs),
                "sample_macs": sorted(all_macs)[:12],
                "suspect_oui": suspect_oui,
                "interfaces": sorted(ifaces),
                "exhausted": exhausted,
                "top_oui_count": top_count if suspect_oui else 0,
            },
            "files": [{"file_id": fid, "events": total_disc, "first_line": 1} for fid in fid_first],
            "related": [{"rule": r["rule"], "description": az.RULE_INFO.get(r["rule"], {}).get("description", r["rule"]),
                         "severity": r["severity"], "ts": r["ts"], "snippet": r["snippet"][:300],
                         "file_id": r["file_id"], "line": r["line_no"], "rel": r["rel"]} for r in related],
            "signals": [],
            "chart": [],
            "top": {},
            "scripts": [],
            "summary": summary,
        }
        top_fid = max(fid_first, key=lambda f: total_disc) if fid_first else None
        if top_fid is not None:
            con.execute(
                "INSERT INTO facts(kind,scope,file_id,line_no,ts,subject,data) VALUES('episode','case',?,?,?,?,?)",
                (top_fid, 1, start, str(n), json.dumps(data)))
            rule = "dhcp_starvation" if exhausted else "dhcp_flood"
            out.append((rule, top_fid, 1, start, end, summary, json.dumps({"episode": n, "end": end})))
    return out, next_episode


def detect_sniffing(con, next_episode=1):

    """Group eavesdropping and traffic-manipulation signals into numbered episodes, continuing the
    episode numbers used by the flood detector. Signals come from the line rules and the pcap reader.
    Dated ones are grouped by a 30-minute gap; undated config traces (rules files, sysctl.d, added CAs,
    dnsmasq spoofing) attach to the nearest dated episode by file mtime, or form one 'standing
    configuration' episode of their own."""
    out = []
    rules = SNIFF_RULES | MITM_RULES
    dated, undated = [], []
    for r in con.execute(
            "SELECT fi.rule, fi.severity, fi.ts, fi.snippet, fi.file_id, fi.line_no, f.rel, f.mtime_ns "
            "FROM findings fi JOIN files f ON f.id = fi.file_id WHERE fi.rule IN (%s) AND fi.scope IN ('line','file') "
            "ORDER BY fi.ts IS NULL, fi.ts" % ",".join("?" * len(rules)), tuple(rules)):
        d = dict(r)
        d["mitm"] = r["rule"] in MITM_RULES
        (dated if r["ts"] else undated).append(d)
    if not dated and not undated:
        return out
    groups = []
    for f in dated:
        m = _minutes(f["ts"])
        if groups and m - groups[-1]["last"] <= 30:
            groups[-1]["items"].append(f)
            groups[-1]["last"] = m
        else:
            groups.append({"first": m, "last": m, "items": [f]})
    standing = []
    for f in undated:
        placed = False
        mt = _minutes(_ns_ts(f["mtime_ns"])) if f["mtime_ns"] else None
        if mt is not None:
            for g in groups:
                if g["first"] - 60 <= mt <= g["last"] + 60:
                    g["items"].append(f)
                    placed = True
                    break
        if not placed:
            standing.append(f)
    techniques = {
        "packet_capture": "sniffer tool run", "packet_capture_file": "capture file",
        "promiscuous_mode": "interface in promiscuous mode", "promiscuous": "promiscuous mode",
        "cleartext_creds": "plaintext credentials captured", "arp_spoof": "ARP spoofing",
        "arp_conflict": "conflicting ARP replies", "traffic_redirect": "traffic redirected / forwarding on",
        "dns_tamper": "DNS tampering", "rogue_ca": "CA certificate added",
    }

    def emit(n, items, a_min, z_min):
        mitm = [x for x in items if x["mitm"]]
        rule = "mitm_episode" if mitm else "sniffing_episode"
        label = "Traffic manipulation / man-in-the-middle" if mitm else "Network eavesdropping"
        start = az.epoch_to_ts(a_min * 60) if a_min is not None else None
        end = (az.epoch_to_ts(z_min * 60)[:16] + ":59") if z_min is not None else None
        kinds = Counter(x["rule"] for x in items)
        files = Counter(x["file_id"] for x in items)
        firsts = {}
        for x in items:
            firsts.setdefault(x["file_id"], x["line_no"])
        bits = [techniques.get(k, k) + (f" x{c}" if c > 1 else "") for k, c in kinds.most_common()]
        creds = [x for x in items if x["rule"] == "cleartext_creds"]
        summary = (f"Episode #{n}, {label}: " + "; ".join(bits)
                   + (f"; {start} to {end}" if start else " (from configuration left in place, time unknown)"))
        data = {"n": n, "title": label, "start": start, "end": end,
                "minutes": (z_min - a_min + 1) if a_min is not None and z_min is not None else None,
                "kind": "sniffing", "mitm": bool(mitm),
                "techniques": [{"rule": k, "label": techniques.get(k, k), "count": c} for k, c in kinds.most_common()],
                "files": [{"file_id": f, "events": c, "first_line": firsts[f]} for f, c in files.most_common()],
                "signals": [{"rule": x["rule"], "severity": x["severity"], "ts": x["ts"], "snippet": x["snippet"][:300],
                             "file_id": x["file_id"], "line": x["line_no"], "rel": x["rel"]} for x in
                            sorted(items, key=lambda x: (x["ts"] or "", x["file_id"]))[:60]],
                "summary": summary}
        anchor = files.most_common(1)[0][0]
        con.execute("INSERT INTO facts(kind, scope, file_id, line_no, ts, subject, data) VALUES('episode','case',?,?,?,?,?)",
                    (anchor, firsts[anchor], start or "", str(n), json.dumps(data)))
        det = json.dumps({"episode": n, "end": end})
        for fid, _c in files.most_common(12):
            out.append((rule, fid, firsts[fid], start, end, summary, det))

    n = next_episode
    for g in groups:
        emit(n, g["items"], g["first"], g["last"])
        n += 1
    if standing:
        emit(n, standing, None, None)
    return out


def episodes_for(con):
    return [json.loads(r[0]) for r in con.execute("SELECT data FROM facts WHERE kind='episode' ORDER BY ts")]
